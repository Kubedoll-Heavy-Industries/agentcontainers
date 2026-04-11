package container

// ComposeRuntime implements the Runtime interface for multi-container
// orchestration via Docker Compose. This enables MCP server sidecars and
// complex service topologies where the agent container needs companion
// services (databases, caches, tool servers, etc.).
//
// Implementation note: rather than importing the Docker Compose Go SDK
// (github.com/docker/compose/v5), which introduces heavyweight transitive
// dependencies on docker/cli and docker/docker, this backend shells out to
// the `docker compose` CLI. This is the officially supported CLI surface,
// keeps go.mod clean, and avoids version-pinning issues between compose-go,
// moby, and docker/cli modules.
//
// Capabilities:
//   - Discover compose files from config or project directory
//   - Manage lifecycle of the full service stack (up / down)
//   - Route exec/logs to the primary (first-listed) service container
//   - Support Compose profiles for optional services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/policy"
)

// composeFileNames lists the file names searched when auto-discovering a
// Compose file in the project directory. The order mirrors what docker
// compose itself looks for.
var composeFileNames = []string{
	"compose.yml",
	"compose.yaml",
	"docker-compose.yml",
	"docker-compose.yaml",
}

// defaultComposeStopTimeout is the graceful shutdown period before
// docker compose down force-kills containers.
const defaultComposeStopTimeout = 10 * time.Second

// Compile-time check that ComposeRuntime satisfies the Runtime interface.
var _ Runtime = (*ComposeRuntime)(nil)

// ---------------------------------------------------------------------------
// Functional options
// ---------------------------------------------------------------------------

// ComposeOption configures a ComposeRuntime.
type ComposeOption func(*composeOptions)

// composeOptions holds the configuration for a ComposeRuntime.
type composeOptions struct {
	logger      *zap.Logger
	projectDir  string
	projectName string
	files       []string // explicit compose file paths
	stopTimeout time.Duration
	envVars     []string // extra env vars passed to docker compose
	profiles    []string // compose profiles to activate
	dockerHost  string   // DOCKER_HOST override (e.g. "unix:///path/to/docker.sock")

	// execFn is the factory used to build *exec.Cmd. It exists purely so
	// unit tests can intercept CLI calls without a real Docker daemon.
	execFn execCmdFactory

	enforcementLevel *enforcement.Level
}

// execCmdFactory builds an *exec.Cmd for the given program and arguments.
// Production code uses exec.CommandContext; tests inject a fake.
type execCmdFactory func(ctx context.Context, name string, args ...string) *exec.Cmd

// defaultComposeOptions returns sensible defaults for the Compose runtime.
func defaultComposeOptions() *composeOptions {
	return &composeOptions{
		logger:      zap.NewNop(),
		stopTimeout: defaultComposeStopTimeout,
		execFn:      exec.CommandContext,
	}
}

// WithComposeLogger sets the structured logger for the Compose runtime.
func WithComposeLogger(l *zap.Logger) ComposeOption {
	return func(o *composeOptions) {
		if l != nil {
			o.logger = l
		}
	}
}

// WithProjectDir sets the working directory for Compose commands.
func WithProjectDir(dir string) ComposeOption {
	return func(o *composeOptions) {
		if dir != "" {
			o.projectDir = dir
		}
	}
}

// WithProjectName overrides the Compose project name (the -p flag).
func WithProjectName(name string) ComposeOption {
	return func(o *composeOptions) {
		if name != "" {
			o.projectName = name
		}
	}
}

// WithComposeFiles explicitly sets the compose file paths (-f flags). If
// not set, the runtime auto-discovers files in the project directory.
func WithComposeFiles(files ...string) ComposeOption {
	return func(o *composeOptions) {
		o.files = append(o.files, files...)
	}
}

// WithComposeStopTimeout sets the graceful shutdown timeout before
// force-killing containers during docker compose down.
func WithComposeStopTimeout(d time.Duration) ComposeOption {
	return func(o *composeOptions) {
		if d > 0 {
			o.stopTimeout = d
		}
	}
}

// WithComposeEnv injects extra environment variables into the docker compose
// subprocess. Each entry must be in KEY=VALUE form.
func WithComposeEnv(vars ...string) ComposeOption {
	return func(o *composeOptions) {
		o.envVars = append(o.envVars, vars...)
	}
}

// WithComposeProfiles activates the given Compose profiles (--profile flags).
func WithComposeProfiles(profiles ...string) ComposeOption {
	return func(o *composeOptions) {
		o.profiles = append(o.profiles, profiles...)
	}
}

// WithDockerHost sets the DOCKER_HOST environment variable for the docker
// compose subprocess, directing it to a specific Docker daemon socket. This
// is used by SandboxRuntime to target the per-VM Docker daemon.
func WithDockerHost(host string) ComposeOption {
	return func(o *composeOptions) {
		if host != "" {
			o.dockerHost = host
		}
	}
}

// withExecFactory replaces the exec.Cmd factory for testing.
func withExecFactory(fn execCmdFactory) ComposeOption {
	return func(o *composeOptions) {
		if fn != nil {
			o.execFn = fn
		}
	}
}

// WithComposeEnforcementLevel sets the enforcement level for the Compose runtime.
// When set to a level other than LevelNone, a Strategy is created during
// NewComposeRuntime and used for container security enforcement.
func WithComposeEnforcementLevel(level enforcement.Level) ComposeOption {
	return func(o *composeOptions) {
		o.enforcementLevel = &level
	}
}

// ---------------------------------------------------------------------------
// ComposeRuntime
// ---------------------------------------------------------------------------

// ComposeRuntime implements the Runtime interface for multi-container
// orchestration via Docker Compose.
type ComposeRuntime struct {
	logger      *zap.Logger
	projectDir  string
	projectName string
	files       []string
	stopTimeout time.Duration
	envVars     []string
	profiles    []string
	dockerHost  string // DOCKER_HOST override for per-VM socket targeting
	execFn      execCmdFactory
	strategy    enforcement.Strategy
}

// NewComposeRuntime creates a new Compose-backed Runtime.
func NewComposeRuntime(opts ...ComposeOption) (*ComposeRuntime, error) {
	o := defaultComposeOptions()
	for _, opt := range opts {
		opt(o)
	}

	c := &ComposeRuntime{
		logger:      o.logger,
		projectDir:  o.projectDir,
		projectName: o.projectName,
		files:       o.files,
		stopTimeout: o.stopTimeout,
		envVars:     o.envVars,
		profiles:    o.profiles,
		dockerHost:  o.dockerHost,
		execFn:      o.execFn,
	}

	// Create enforcement strategy if a level was requested.
	if o.enforcementLevel != nil && *o.enforcementLevel != enforcement.LevelNone {
		level := *o.enforcementLevel
		c.strategy = enforcement.NewStrategy(level)
		c.logger.Info("enforcement strategy configured",
			zap.String("level", level.String()),
		)
	}

	return c, nil
}

// ---------------------------------------------------------------------------
// Runtime interface implementation
// ---------------------------------------------------------------------------

// Start resolves the Compose file(s) for the given configuration, then runs
// docker compose up -d to start all services in the background.
//
// Policy enforcement in Compose is limited compared to the Docker runtime.
// For M0, we pass policy settings via environment variables that Compose files
// can reference. Full policy enforcement (CapDrop, SecurityOpt, ReadonlyRootfs)
// requires either:
//   - A Compose file that explicitly references these settings
//   - Post-creation container modification (not currently implemented)
//   - Using the Docker runtime for single-container workloads
func (c *ComposeRuntime) Start(ctx context.Context, cfg *config.AgentContainer, opts StartOptions) (*Session, error) {
	files, err := c.resolveComposeFiles(cfg, opts)
	if err != nil {
		return nil, fmt.Errorf("compose runtime: %w", err)
	}

	projectName := c.deriveProjectName(cfg)

	c.logger.Info("starting compose project",
		zap.String("project", projectName),
		zap.Strings("files", files),
	)

	args := c.baseArgs(files, projectName)
	args = append(args, "up", "-d")

	if cfg.Image != "" && cfg.Build == nil {
		args = append(args, "--pull", "always")
	}

	env := c.buildEnvWithPolicy(opts.Policy)

	if stdout, stderr, runErr := c.run(ctx, args, env, opts.WorkspacePath); runErr != nil {
		return nil, fmt.Errorf("compose runtime: starting project %s: %w\nstdout: %s\nstderr: %s",
			projectName, runErr, stdout, stderr)
	}

	c.logger.Info("compose project started", zap.String("project", projectName))

	// Resolve policy for enforcement.
	p := opts.Policy
	if p == nil {
		p = defaultContainerPolicy()
	}

	// Pre-start enforcement.
	if c.strategy != nil {
		if err := c.strategy.Apply(ctx, projectName, 0, p); err != nil {
			// Best-effort cleanup.
			downArgs := c.baseArgs(files, projectName)
			downArgs = append(downArgs, "down", "--remove-orphans", "--volumes")
			_, _, _ = c.run(ctx, downArgs, c.buildEnv(), opts.WorkspacePath)
			return nil, fmt.Errorf("compose runtime: pre-start enforcement: %w", err)
		}
		c.logger.Info("pre-start enforcement applied",
			zap.String("project", projectName),
			zap.String("level", c.strategy.Level().String()),
		)
	}

	return &Session{
		ContainerID: projectName,
		RuntimeType: RuntimeCompose,
		Status:      "running",
		CreatedAt:   time.Now(),
	}, nil
}

// Stop runs docker compose down for the project.
func (c *ComposeRuntime) Stop(ctx context.Context, session *Session) error {
	if session == nil {
		return fmt.Errorf("compose runtime: nil session")
	}

	c.logger.Info("stopping compose project", zap.String("project", session.ContainerID))

	// Remove enforcement before stopping the project.
	if c.strategy != nil {
		if err := c.strategy.Remove(ctx, session.ContainerID); err != nil {
			c.logger.Warn("failed to remove enforcement, continuing with stop",
				zap.String("project", session.ContainerID),
				zap.Error(err),
			)
		}
	}

	args := c.baseArgs(c.files, session.ContainerID)
	args = append(args, "down",
		"--remove-orphans",
		"--volumes",
		"--timeout", fmt.Sprintf("%d", int(c.stopTimeout.Seconds())),
	)

	if stdout, stderr, err := c.run(ctx, args, c.buildEnv(), c.projectDir); err != nil {
		return fmt.Errorf("compose runtime: stopping project %s: %w\nstdout: %s\nstderr: %s",
			session.ContainerID, err, stdout, stderr)
	}

	session.Status = "stopped"
	c.logger.Info("compose project stopped", zap.String("project", session.ContainerID))
	return nil
}

// Exec runs a command inside the primary service container.
func (c *ComposeRuntime) Exec(ctx context.Context, session *Session, cmd []string) (*ExecResult, error) {
	if session == nil {
		return nil, fmt.Errorf("compose runtime: nil session")
	}
	if len(cmd) == 0 {
		return nil, fmt.Errorf("compose runtime: empty command")
	}

	service, err := c.primaryService(ctx, session.ContainerID)
	if err != nil {
		return nil, fmt.Errorf("compose runtime: resolving primary service: %w", err)
	}

	args := c.baseArgs(c.files, session.ContainerID)
	args = append(args, "exec", "-T", service)
	args = append(args, cmd...)

	stdout, stderr, execErr := c.run(ctx, args, c.buildEnv(), c.projectDir)

	exitCode := 0
	if execErr != nil {
		var exitErr *exec.ExitError
		if ok := extractExitError(execErr, &exitErr); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("compose runtime: executing command in %s/%s: %w",
				session.ContainerID, service, execErr)
		}
	}

	return &ExecResult{
		ExitCode: exitCode,
		Stdout:   []byte(stdout),
		Stderr:   []byte(stderr),
	}, nil
}

// Logs returns a ReadCloser that streams the combined logs of all services.
func (c *ComposeRuntime) Logs(ctx context.Context, session *Session) (io.ReadCloser, error) {
	if session == nil {
		return nil, fmt.Errorf("compose runtime: nil session")
	}

	args := c.baseArgs(c.files, session.ContainerID)
	args = append(args, "logs", "--follow", "--no-log-prefix")

	cmdCtx, cancel := context.WithCancel(ctx)
	cmd := c.execFn(cmdCtx, "docker", args...)
	cmd.Dir = c.projectDir
	cmd.Env = c.buildEnv()

	pipe, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("compose runtime: creating log pipe: %w", err)
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("compose runtime: starting log stream: %w", err)
	}

	return &logReadCloser{
		ReadCloser: pipe,
		cmd:        cmd,
		cancel:     cancel,
	}, nil
}

// composePsEntry represents a single container entry from
// docker compose ps --format json. Each line of the output is one JSON object.
type composePsEntry struct {
	ID        string `json:"ID"`
	Name      string `json:"Name"`
	Service   string `json:"Service"`
	State     string `json:"State"`
	Image     string `json:"Image"`
	CreatedAt string `json:"CreatedAt"`
}

// List returns all sessions for the Compose project by running
// docker compose ps --format json and parsing the NDJSON output. When all is
// false, only containers in the "running" state are returned. An empty project
// (no containers) returns an empty slice with no error.
func (c *ComposeRuntime) List(ctx context.Context, all bool) ([]*Session, error) {
	args := c.baseArgs(c.files, c.projectName)
	args = append(args, "ps", "--format", "json")
	if all {
		args = append(args, "-a")
	}

	stdout, stderr, err := c.run(ctx, args, c.buildEnv(), c.projectDir)
	if err != nil {
		// docker compose ps returns an error when the project has no containers
		// or the project doesn't exist. Treat this as an empty result if stderr
		// contains typical "no such" or "no configuration" messages.
		if strings.Contains(stderr, "no configuration file") ||
			strings.Contains(stderr, "no such") ||
			strings.Contains(stdout, "no such") {
			return []*Session{}, nil
		}
		return nil, fmt.Errorf("compose runtime: listing containers: %w\nstderr: %s", err, stderr)
	}

	stdout = strings.TrimSpace(stdout)
	if stdout == "" {
		return []*Session{}, nil
	}

	entries, err := parseComposePsOutput(stdout)
	if err != nil {
		return nil, fmt.Errorf("compose runtime: parsing ps output: %w", err)
	}

	sessions := make([]*Session, 0, len(entries))
	for _, e := range entries {
		// When all is false, docker compose ps already filters to running
		// containers (no -a flag). But as a safety net, also filter here in
		// case the compose CLI version behaves differently.
		if !all && !strings.EqualFold(e.State, "running") {
			continue
		}

		var createdAt time.Time
		if e.CreatedAt != "" {
			// docker compose ps uses ISO 8601 format for CreatedAt.
			if t, parseErr := time.Parse("2006-01-02 15:04:05 -0700 MST", e.CreatedAt); parseErr == nil {
				createdAt = t
			}
		}

		sessions = append(sessions, &Session{
			ContainerID: e.ID,
			Name:        e.Name,
			Image:       e.Image,
			RuntimeType: RuntimeCompose,
			Status:      e.State,
			CreatedAt:   createdAt,
		})
	}

	return sessions, nil
}

// parseComposePsOutput parses the NDJSON output from docker compose ps.
// The output may be either a JSON array (newer compose versions) or
// newline-delimited JSON objects (older compose versions).
func parseComposePsOutput(output string) ([]composePsEntry, error) {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil, nil
	}

	// Try parsing as a JSON array first (newer docker compose versions).
	if strings.HasPrefix(output, "[") {
		var entries []composePsEntry
		if err := json.Unmarshal([]byte(output), &entries); err == nil {
			return entries, nil
		}
	}

	// Fall back to parsing as newline-delimited JSON objects.
	var entries []composePsEntry
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry composePsEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, fmt.Errorf("parsing compose ps line %q: %w", line, err)
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// ---------------------------------------------------------------------------
// Compose file resolution
// ---------------------------------------------------------------------------

// resolveComposeFiles determines the compose file path(s) to use.
func (c *ComposeRuntime) resolveComposeFiles(cfg *config.AgentContainer, opts StartOptions) ([]string, error) {
	_ = cfg // reserved for future use (e.g. reading dockerComposeFile from config)

	if len(c.files) > 0 {
		return c.files, nil
	}

	searchDir := c.projectDir
	if searchDir == "" {
		searchDir = opts.WorkspacePath
	}
	if searchDir == "" {
		return nil, fmt.Errorf("no project directory or workspace path specified for compose file discovery")
	}

	found := discoverComposeFiles(searchDir)
	if len(found) == 0 {
		return nil, fmt.Errorf("no compose file found in %s (searched for %s)",
			searchDir, strings.Join(composeFileNames, ", "))
	}

	return found, nil
}

// discoverComposeFiles searches dir for well-known compose file names.
func discoverComposeFiles(dir string) []string {
	for _, name := range composeFileNames {
		abs := filepath.Join(dir, name)
		if _, err := os.Stat(abs); err == nil {
			return []string{abs}
		}
	}
	return nil
}

// deriveProjectName computes the Compose project name.
func (c *ComposeRuntime) deriveProjectName(cfg *config.AgentContainer) string {
	if c.projectName != "" {
		return c.projectName
	}
	if cfg.Name != "" {
		return sanitiseProjectName(cfg.Name)
	}
	if c.projectDir != "" {
		return sanitiseProjectName(filepath.Base(c.projectDir))
	}
	return "agentcontainer"
}

// sanitiseProjectName normalises a string into a valid Compose project name.
func sanitiseProjectName(name string) string {
	name = strings.ToLower(name)
	var b strings.Builder
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			if i == 0 {
				b.WriteRune('_')
			}
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	s := b.String()
	if s == "" {
		return "agentcontainer"
	}
	return s
}

// ---------------------------------------------------------------------------
// Primary service resolution
// ---------------------------------------------------------------------------

// primaryService determines the primary service of the compose project.
func (c *ComposeRuntime) primaryService(ctx context.Context, projectName string) (string, error) {
	args := c.baseArgs(c.files, projectName)
	args = append(args, "ps", "--services", "--filter", "status=running")

	stdout, _, err := c.run(ctx, args, c.buildEnv(), c.projectDir)
	if err == nil {
		services := nonEmptyLines(stdout)
		if len(services) > 0 {
			return services[0], nil
		}
	}

	args = c.baseArgs(c.files, projectName)
	args = append(args, "config", "--services")

	stdout, _, err = c.run(ctx, args, c.buildEnv(), c.projectDir)
	if err != nil {
		return "", fmt.Errorf("listing services: %w", err)
	}

	services := nonEmptyLines(stdout)
	if len(services) == 0 {
		return "", fmt.Errorf("compose project %s has no services", projectName)
	}
	return services[0], nil
}

// ---------------------------------------------------------------------------
// CLI helpers
// ---------------------------------------------------------------------------

// baseArgs builds the shared docker compose arguments.
func (c *ComposeRuntime) baseArgs(files []string, projectName string) []string {
	args := []string{"compose"}

	for _, f := range files {
		args = append(args, "-f", f)
	}

	if projectName != "" {
		args = append(args, "-p", projectName)
	}

	for _, p := range c.profiles {
		args = append(args, "--profile", p)
	}

	return args
}

// buildEnv constructs the environment for the docker compose subprocess.
// When dockerHost is set, it overrides the DOCKER_HOST environment variable
// so the compose CLI targets a specific Docker daemon (e.g. a per-VM socket).
func (c *ComposeRuntime) buildEnv() []string {
	env := os.Environ()
	env = append(env, c.envVars...)
	if c.dockerHost != "" {
		env = append(env, "DOCKER_HOST="+c.dockerHost)
	}
	return env
}

// buildEnvWithPolicy constructs the environment for the docker compose
// subprocess with policy settings exposed as environment variables. Compose
// files can reference these variables to apply security settings.
//
// Exposed variables:
//   - AC_POLICY_NETWORK_MODE: "none" or "bridge"
//   - AC_POLICY_READONLY_ROOTFS: "true" or "false"
//   - AC_POLICY_CAP_DROP: comma-separated list of capabilities to drop
//   - AC_POLICY_CAP_ADD: comma-separated list of capabilities to add
//   - AC_POLICY_SECURITY_OPT: comma-separated list of security options
func (c *ComposeRuntime) buildEnvWithPolicy(p *policy.ContainerPolicy) []string {
	env := c.buildEnv()

	if p == nil {
		// Apply default-deny settings via environment variables.
		env = append(env,
			"AC_POLICY_NETWORK_MODE=none",
			"AC_POLICY_READONLY_ROOTFS=true",
			"AC_POLICY_CAP_DROP=ALL",
			"AC_POLICY_CAP_ADD=",
			"AC_POLICY_SECURITY_OPT=no-new-privileges",
		)
		return env
	}

	env = append(env, fmt.Sprintf("AC_POLICY_NETWORK_MODE=%s", p.NetworkMode))
	env = append(env, fmt.Sprintf("AC_POLICY_READONLY_ROOTFS=%t", p.ReadonlyRootfs))

	if len(p.CapDrop) > 0 {
		env = append(env, fmt.Sprintf("AC_POLICY_CAP_DROP=%s", strings.Join(p.CapDrop, ",")))
	} else {
		env = append(env, "AC_POLICY_CAP_DROP=")
	}

	if len(p.CapAdd) > 0 {
		env = append(env, fmt.Sprintf("AC_POLICY_CAP_ADD=%s", strings.Join(p.CapAdd, ",")))
	} else {
		env = append(env, "AC_POLICY_CAP_ADD=")
	}

	if len(p.SecurityOpt) > 0 {
		env = append(env, fmt.Sprintf("AC_POLICY_SECURITY_OPT=%s", strings.Join(p.SecurityOpt, ",")))
	} else {
		env = append(env, "AC_POLICY_SECURITY_OPT=")
	}

	return env
}

// run executes a docker CLI command with captured stdout and stderr.
func (c *ComposeRuntime) run(ctx context.Context, args, env []string, workDir string) (string, string, error) {
	cmd := c.execFn(ctx, "docker", args...)

	if workDir != "" {
		cmd.Dir = workDir
	} else if c.projectDir != "" {
		cmd.Dir = c.projectDir
	}
	cmd.Env = env

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	c.logger.Debug("running compose command",
		zap.String("cmd", "docker"),
		zap.Strings("args", args),
		zap.String("dir", cmd.Dir),
	)

	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// ---------------------------------------------------------------------------
// Log stream helper
// ---------------------------------------------------------------------------

// logReadCloser wraps a docker compose logs --follow process pipe.
type logReadCloser struct {
	io.ReadCloser
	cmd    *exec.Cmd
	cancel context.CancelFunc
}

// Close terminates the log stream subprocess and releases resources.
func (l *logReadCloser) Close() error {
	l.cancel()
	pipeErr := l.ReadCloser.Close()
	_ = l.cmd.Wait()
	return pipeErr
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

// nonEmptyLines splits s on newlines and returns only non-empty lines.
func nonEmptyLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

// extractExitError unwraps err into an *exec.ExitError if possible.
func extractExitError(err error, target **exec.ExitError) bool {
	return errors.As(err, target)
}
