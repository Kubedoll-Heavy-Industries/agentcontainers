package container

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/policy"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/secrets"
)

func TestNewComposeRuntime_Defaults(t *testing.T) {
	rt, err := NewComposeRuntime()
	require.NoError(t, err)

	assert.NotNil(t, rt.logger)
	assert.Equal(t, defaultComposeStopTimeout, rt.stopTimeout)
	assert.Empty(t, rt.projectDir)
	assert.Empty(t, rt.projectName)
	assert.Empty(t, rt.files)
	assert.Empty(t, rt.envVars)
	assert.Empty(t, rt.profiles)
	assert.NotNil(t, rt.execFn)
}

func TestComposeOptions(t *testing.T) {
	t.Run("WithComposeLogger", func(t *testing.T) {
		l := zap.NewExample()
		rt, err := NewComposeRuntime(WithComposeLogger(l))
		require.NoError(t, err)
		assert.Equal(t, l, rt.logger)
	})

	t.Run("WithComposeLogger nil ignored", func(t *testing.T) {
		rt, err := NewComposeRuntime(WithComposeLogger(nil))
		require.NoError(t, err)
		assert.NotNil(t, rt.logger)
	})

	t.Run("WithProjectDir", func(t *testing.T) {
		rt, err := NewComposeRuntime(WithProjectDir("/some/path"))
		require.NoError(t, err)
		assert.Equal(t, "/some/path", rt.projectDir)
	})

	t.Run("WithProjectDir empty ignored", func(t *testing.T) {
		rt, err := NewComposeRuntime(WithProjectDir(""))
		require.NoError(t, err)
		assert.Empty(t, rt.projectDir)
	})

	t.Run("WithProjectName", func(t *testing.T) {
		rt, err := NewComposeRuntime(WithProjectName("myproject"))
		require.NoError(t, err)
		assert.Equal(t, "myproject", rt.projectName)
	})

	t.Run("WithComposeFiles", func(t *testing.T) {
		rt, err := NewComposeRuntime(WithComposeFiles("a.yml", "b.yml"))
		require.NoError(t, err)
		assert.Equal(t, []string{"a.yml", "b.yml"}, rt.files)
	})

	t.Run("WithComposeFiles accumulates", func(t *testing.T) {
		rt, err := NewComposeRuntime(
			WithComposeFiles("a.yml"),
			WithComposeFiles("b.yml"),
		)
		require.NoError(t, err)
		assert.Equal(t, []string{"a.yml", "b.yml"}, rt.files)
	})

	t.Run("WithComposeStopTimeout positive", func(t *testing.T) {
		rt, err := NewComposeRuntime(WithComposeStopTimeout(30 * time.Second))
		require.NoError(t, err)
		assert.Equal(t, 30*time.Second, rt.stopTimeout)
	})

	t.Run("WithComposeStopTimeout zero ignored", func(t *testing.T) {
		rt, err := NewComposeRuntime(WithComposeStopTimeout(0))
		require.NoError(t, err)
		assert.Equal(t, defaultComposeStopTimeout, rt.stopTimeout)
	})

	t.Run("WithComposeEnv", func(t *testing.T) {
		rt, err := NewComposeRuntime(WithComposeEnv("FOO=bar", "BAZ=qux"))
		require.NoError(t, err)
		assert.Equal(t, []string{"FOO=bar", "BAZ=qux"}, rt.envVars)
	})

	t.Run("WithComposeProfiles", func(t *testing.T) {
		rt, err := NewComposeRuntime(WithComposeProfiles("debug", "monitoring"))
		require.NoError(t, err)
		assert.Equal(t, []string{"debug", "monitoring"}, rt.profiles)
	})
}

func TestDiscoverComposeFiles(t *testing.T) {
	t.Run("compose.yml", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "compose.yml"), []byte("services:\n"), 0644))

		found := discoverComposeFiles(dir)
		require.Len(t, found, 1)
		assert.Equal(t, filepath.Join(dir, "compose.yml"), found[0])
	})

	t.Run("docker-compose.yml", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("services:\n"), 0644))

		found := discoverComposeFiles(dir)
		require.Len(t, found, 1)
		assert.Equal(t, filepath.Join(dir, "docker-compose.yml"), found[0])
	})

	t.Run("priority order", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "compose.yml"), []byte("s:\n"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("s:\n"), 0644))

		found := discoverComposeFiles(dir)
		require.Len(t, found, 1)
		assert.Equal(t, filepath.Join(dir, "compose.yml"), found[0])
	})

	t.Run("none found", func(t *testing.T) {
		dir := t.TempDir()
		found := discoverComposeFiles(dir)
		assert.Empty(t, found)
	})
}

func TestDeriveProjectName(t *testing.T) {
	t.Run("explicit option", func(t *testing.T) {
		rt, _ := NewComposeRuntime(WithProjectName("explicit"))
		name := rt.deriveProjectName(&config.AgentContainer{Name: "config-name"})
		assert.Equal(t, "explicit", name)
	})

	t.Run("from config", func(t *testing.T) {
		rt, _ := NewComposeRuntime()
		name := rt.deriveProjectName(&config.AgentContainer{Name: "My Agent"})
		assert.Equal(t, "my-agent", name)
	})

	t.Run("from project dir", func(t *testing.T) {
		rt, _ := NewComposeRuntime(WithProjectDir("/home/user/myproject"))
		name := rt.deriveProjectName(&config.AgentContainer{})
		assert.Equal(t, "myproject", name)
	})

	t.Run("fallback", func(t *testing.T) {
		rt, _ := NewComposeRuntime()
		name := rt.deriveProjectName(&config.AgentContainer{})
		assert.Equal(t, "agentcontainer", name)
	})
}

func TestSanitiseProjectName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple lowercase", "myproject", "myproject"},
		{"mixed case", "MyProject", "myproject"},
		{"with spaces", "my project", "my-project"},
		{"with dots", "my.project.name", "my-project-name"},
		{"starts with number", "123project", "_123project"},
		{"hyphens and underscores preserved", "my-project_name", "my-project_name"},
		{"empty string", "", "agentcontainer"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, sanitiseProjectName(tc.input))
		})
	}
}

func TestNonEmptyLines(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"single line", "hello", []string{"hello"}},
		{"multiple lines", "a\nb\nc", []string{"a", "b", "c"}},
		{"with empty lines", "a\n\nb\n\n", []string{"a", "b"}},
		{"empty string", "", nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, nonEmptyLines(tc.input))
		})
	}
}

func TestBaseArgs(t *testing.T) {
	t.Run("no files no project", func(t *testing.T) {
		rt, _ := NewComposeRuntime()
		assert.Equal(t, []string{"compose"}, rt.baseArgs(nil, ""))
	})

	t.Run("with files", func(t *testing.T) {
		rt, _ := NewComposeRuntime()
		args := rt.baseArgs([]string{"/a/compose.yml", "/b/override.yml"}, "")
		assert.Equal(t, []string{"compose", "-f", "/a/compose.yml", "-f", "/b/override.yml"}, args)
	})

	t.Run("with project name", func(t *testing.T) {
		rt, _ := NewComposeRuntime()
		args := rt.baseArgs(nil, "myproject")
		assert.Equal(t, []string{"compose", "-p", "myproject"}, args)
	})

	t.Run("with profiles", func(t *testing.T) {
		rt, _ := NewComposeRuntime(WithComposeProfiles("debug", "test"))
		args := rt.baseArgs(nil, "")
		assert.Equal(t, []string{"compose", "--profile", "debug", "--profile", "test"}, args)
	})
}

func TestResolveComposeFiles(t *testing.T) {
	t.Run("explicit files", func(t *testing.T) {
		rt, _ := NewComposeRuntime(WithComposeFiles("/a/compose.yml"))
		files, err := rt.resolveComposeFiles(&config.AgentContainer{}, StartOptions{})
		require.NoError(t, err)
		assert.Equal(t, []string{"/a/compose.yml"}, files)
	})

	t.Run("auto-discover from project dir", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "compose.yml"), []byte("s:\n"), 0644))

		rt, _ := NewComposeRuntime(WithProjectDir(dir))
		files, err := rt.resolveComposeFiles(&config.AgentContainer{}, StartOptions{})
		require.NoError(t, err)
		require.Len(t, files, 1)
		assert.Equal(t, filepath.Join(dir, "compose.yml"), files[0])
	})

	t.Run("fallback to workspace path", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("s:\n"), 0644))

		rt, _ := NewComposeRuntime()
		files, err := rt.resolveComposeFiles(&config.AgentContainer{}, StartOptions{WorkspacePath: dir})
		require.NoError(t, err)
		require.Len(t, files, 1)
	})

	t.Run("no directory error", func(t *testing.T) {
		rt, _ := NewComposeRuntime()
		_, err := rt.resolveComposeFiles(&config.AgentContainer{}, StartOptions{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no project directory or workspace path")
	})

	t.Run("no file found error", func(t *testing.T) {
		dir := t.TempDir()
		rt, _ := NewComposeRuntime(WithProjectDir(dir))
		_, err := rt.resolveComposeFiles(&config.AgentContainer{}, StartOptions{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no compose file found")
	})
}

func TestComposeRuntime_NilSessionGuards(t *testing.T) {
	rt, _ := NewComposeRuntime()

	t.Run("Stop nil session", func(t *testing.T) {
		err := rt.Stop(context.Background(), nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil session")
	})

	t.Run("Exec nil session", func(t *testing.T) {
		_, err := rt.Exec(context.Background(), nil, []string{"echo"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil session")
	})

	t.Run("Exec empty command", func(t *testing.T) {
		session := &Session{ContainerID: "test", RuntimeType: RuntimeCompose}
		_, err := rt.Exec(context.Background(), session, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty command")
	})

	t.Run("Logs nil session", func(t *testing.T) {
		_, err := rt.Logs(context.Background(), nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil session")
	})
}

// ---------------------------------------------------------------------------
// Policy environment variable tests
// ---------------------------------------------------------------------------

func TestBuildEnvWithPolicy_NilPolicy(t *testing.T) {
	rt, err := NewComposeRuntime()
	require.NoError(t, err)

	env := rt.buildEnvWithPolicy(nil)

	// Should contain default-deny policy settings.
	envMap := envSliceToMap(env)
	assert.Equal(t, "none", envMap["AC_POLICY_NETWORK_MODE"], "nil policy should set network mode to none")
	assert.Equal(t, "true", envMap["AC_POLICY_READONLY_ROOTFS"], "nil policy should set readonly rootfs to true")
	assert.Equal(t, "ALL", envMap["AC_POLICY_CAP_DROP"], "nil policy should drop all capabilities")
	assert.Equal(t, "", envMap["AC_POLICY_CAP_ADD"], "nil policy should not add any capabilities")
	assert.Equal(t, "no-new-privileges", envMap["AC_POLICY_SECURITY_OPT"], "nil policy should set no-new-privileges")
}

func TestBuildEnvWithPolicy_CustomPolicy(t *testing.T) {
	rt, err := NewComposeRuntime()
	require.NoError(t, err)

	p := &policy.ContainerPolicy{
		CapDrop:        []string{"NET_ADMIN", "SYS_ADMIN"},
		CapAdd:         []string{"NET_BIND_SERVICE"},
		SecurityOpt:    []string{"no-new-privileges", "seccomp=unconfined"},
		ReadonlyRootfs: false,
		NetworkMode:    "bridge",
	}

	env := rt.buildEnvWithPolicy(p)

	envMap := envSliceToMap(env)
	assert.Equal(t, "bridge", envMap["AC_POLICY_NETWORK_MODE"], "should apply network mode from policy")
	assert.Equal(t, "false", envMap["AC_POLICY_READONLY_ROOTFS"], "should apply readonly rootfs from policy")
	assert.Equal(t, "NET_ADMIN,SYS_ADMIN", envMap["AC_POLICY_CAP_DROP"], "should apply cap drop from policy")
	assert.Equal(t, "NET_BIND_SERVICE", envMap["AC_POLICY_CAP_ADD"], "should apply cap add from policy")
	assert.Equal(t, "no-new-privileges,seccomp=unconfined", envMap["AC_POLICY_SECURITY_OPT"], "should apply security opt from policy")
}

func TestBuildEnvWithPolicy_EmptySlices(t *testing.T) {
	rt, err := NewComposeRuntime()
	require.NoError(t, err)

	p := &policy.ContainerPolicy{
		CapDrop:        []string{},
		CapAdd:         []string{},
		SecurityOpt:    []string{},
		ReadonlyRootfs: true,
		NetworkMode:    "none",
	}

	env := rt.buildEnvWithPolicy(p)

	envMap := envSliceToMap(env)
	assert.Equal(t, "", envMap["AC_POLICY_CAP_DROP"], "empty cap drop should produce empty string")
	assert.Equal(t, "", envMap["AC_POLICY_CAP_ADD"], "empty cap add should produce empty string")
	assert.Equal(t, "", envMap["AC_POLICY_SECURITY_OPT"], "empty security opt should produce empty string")
}

func TestBuildEnvWithPolicy_IncludesExistingEnv(t *testing.T) {
	rt, err := NewComposeRuntime(WithComposeEnv("CUSTOM_VAR=value"))
	require.NoError(t, err)

	env := rt.buildEnvWithPolicy(nil)

	envMap := envSliceToMap(env)
	assert.Equal(t, "value", envMap["CUSTOM_VAR"], "should include existing env vars")
	assert.Equal(t, "none", envMap["AC_POLICY_NETWORK_MODE"], "should also include policy env vars")
}

// envSliceToMap converts a slice of KEY=value strings to a map for easier testing.
func envSliceToMap(env []string) map[string]string {
	m := make(map[string]string)
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			m[parts[0]] = parts[1]
		}
	}
	return m
}

// ---------------------------------------------------------------------------
// Enforcement strategy tests
// ---------------------------------------------------------------------------

// composeTestStrategy implements enforcement.Strategy for testing.
type composeTestStrategy struct {
	level     enforcement.Level
	applied   []string
	removed   []string
	applyErr  error
	removeErr error
	mu        sync.Mutex
}

var _ enforcement.Strategy = (*composeTestStrategy)(nil)

func (s *composeTestStrategy) Apply(_ context.Context, containerID string, _ uint32, _ *policy.ContainerPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applied = append(s.applied, containerID)
	return s.applyErr
}
func (s *composeTestStrategy) Update(_ context.Context, _ string, _ *policy.ContainerPolicy) error {
	return nil
}
func (s *composeTestStrategy) Remove(_ context.Context, containerID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removed = append(s.removed, containerID)
	return s.removeErr
}
func (s *composeTestStrategy) InjectSecrets(_ context.Context, _ string, _ map[string]*secrets.Secret) error {
	return nil
}
func (s *composeTestStrategy) Events(_ string) <-chan enforcement.Event { return nil }
func (s *composeTestStrategy) Level() enforcement.Level                 { return s.level }

func TestComposeOptions_WithEnforcementLevel(t *testing.T) {
	opts := defaultComposeOptions()
	assert.Nil(t, opts.enforcementLevel, "enforcement level should be nil by default")

	level := enforcement.LevelGRPC
	WithComposeEnforcementLevel(level)(opts)

	require.NotNil(t, opts.enforcementLevel, "enforcement level should be set")
	assert.Equal(t, enforcement.LevelGRPC, *opts.enforcementLevel)
}

func TestNewComposeRuntime_WithEnforcementLevel_None(t *testing.T) {
	rt, err := NewComposeRuntime(WithComposeEnforcementLevel(enforcement.LevelNone))
	require.NoError(t, err)
	assert.Nil(t, rt.strategy, "LevelNone should not create a strategy")
}

// fakeExecFn returns an exec factory that records calls but always succeeds.
// It fakes "docker compose ps" to return a service name and "docker compose up"
// to succeed.
func fakeExecFn(calls *[][]string, mu *sync.Mutex) execCmdFactory {
	return func(ctx context.Context, name string, args ...string) *exec.Cmd {
		mu.Lock()
		fullArgs := append([]string{name}, args...)
		*calls = append(*calls, fullArgs)
		mu.Unlock()

		// For "docker compose ... ps --services --filter ..." return a service name.
		for i, a := range args {
			if a == "ps" && i+1 < len(args) {
				return exec.CommandContext(ctx, "echo", "web")
			}
			if a == "config" && i+1 < len(args) && args[i+1] == "--services" {
				return exec.CommandContext(ctx, "echo", "web")
			}
		}

		// For everything else, just succeed.
		return exec.CommandContext(ctx, "true")
	}
}

func TestComposeRuntime_Start_AppliesEnforcement(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "compose.yml"), []byte("services:\n  web:\n    image: alpine\n"), 0644))

	strategy := &composeTestStrategy{level: enforcement.LevelGRPC}

	var calls [][]string
	var mu sync.Mutex

	rt, err := NewComposeRuntime(
		WithComposeLogger(zap.NewNop()),
		WithProjectDir(dir),
		withExecFactory(fakeExecFn(&calls, &mu)),
	)
	require.NoError(t, err)
	rt.strategy = strategy

	session, err := rt.Start(context.Background(), &config.AgentContainer{
		Name:  "test-enforce",
		Image: "alpine",
	}, StartOptions{
		Policy: &policy.ContainerPolicy{
			CapDrop:        []string{"ALL"},
			SecurityOpt:    []string{"no-new-privileges"},
			ReadonlyRootfs: true,
			NetworkMode:    "bridge",
			AllowedHosts:   []string{"example.com"},
		},
	})
	require.NoError(t, err)
	assert.NotNil(t, session)

	// Strategy.Apply should have been called with the project name.
	assert.Len(t, strategy.applied, 1, "Apply should have been called once")
	assert.Equal(t, session.ContainerID, strategy.applied[0])
}

func TestComposeRuntime_Start_EnforcementFailure_CleansUp(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "compose.yml"), []byte("services:\n  web:\n    image: alpine\n"), 0644))

	strategy := &composeTestStrategy{
		level:    enforcement.LevelGRPC,
		applyErr: fmt.Errorf("bpf attach failed"),
	}

	var calls [][]string
	var mu sync.Mutex

	rt, err := NewComposeRuntime(
		WithComposeLogger(zap.NewNop()),
		WithProjectDir(dir),
		withExecFactory(fakeExecFn(&calls, &mu)),
	)
	require.NoError(t, err)
	rt.strategy = strategy

	session, err := rt.Start(context.Background(), &config.AgentContainer{
		Name:  "test-enforce-fail",
		Image: "alpine",
	}, StartOptions{
		Policy: &policy.ContainerPolicy{
			CapDrop:        []string{"ALL"},
			SecurityOpt:    []string{"no-new-privileges"},
			ReadonlyRootfs: true,
			NetworkMode:    "bridge",
			AllowedHosts:   []string{"example.com"},
		},
	})
	assert.Error(t, err)
	assert.Nil(t, session)
	assert.Contains(t, err.Error(), "pre-start enforcement")

	// Should have attempted compose down for cleanup.
	mu.Lock()
	defer mu.Unlock()
	hasDown := false
	for _, c := range calls {
		for _, arg := range c {
			if arg == "down" {
				hasDown = true
			}
		}
	}
	assert.True(t, hasDown, "should run compose down on enforcement failure")
}

func TestComposeRuntime_Stop_RemovesEnforcement(t *testing.T) {
	strategy := &composeTestStrategy{level: enforcement.LevelGRPC}

	var calls [][]string
	var mu sync.Mutex

	rt, err := NewComposeRuntime(
		WithComposeLogger(zap.NewNop()),
		withExecFactory(fakeExecFn(&calls, &mu)),
	)
	require.NoError(t, err)
	rt.strategy = strategy

	session := &Session{
		ContainerID: "test-project",
		RuntimeType: RuntimeCompose,
		Status:      "running",
	}

	err = rt.Stop(context.Background(), session)
	require.NoError(t, err)

	// Strategy.Remove should have been called.
	assert.Len(t, strategy.removed, 1, "Remove should have been called once")
	assert.Equal(t, "test-project", strategy.removed[0])
}

func TestComposeRuntime_Stop_EnforcementRemoveError_ContinuesWithStop(t *testing.T) {
	strategy := &composeTestStrategy{
		level:     enforcement.LevelGRPC,
		removeErr: fmt.Errorf("cleanup failed"),
	}

	var calls [][]string
	var mu sync.Mutex

	rt, err := NewComposeRuntime(
		WithComposeLogger(zap.NewNop()),
		withExecFactory(fakeExecFn(&calls, &mu)),
	)
	require.NoError(t, err)
	rt.strategy = strategy

	session := &Session{
		ContainerID: "test-project",
		RuntimeType: RuntimeCompose,
		Status:      "running",
	}

	// Stop should still succeed even if enforcement removal fails.
	err = rt.Stop(context.Background(), session)
	require.NoError(t, err)
	assert.Equal(t, "stopped", session.Status)
}

func TestComposeRuntime_NoStrategy_NoEnforcement(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "compose.yml"), []byte("services:\n  web:\n    image: alpine\n"), 0644))

	var calls [][]string
	var mu sync.Mutex

	rt, err := NewComposeRuntime(
		WithComposeLogger(zap.NewNop()),
		WithProjectDir(dir),
		withExecFactory(fakeExecFn(&calls, &mu)),
	)
	require.NoError(t, err)

	// No strategy should be set.
	assert.Nil(t, rt.strategy)

	// Start should succeed without enforcement.
	session, err := rt.Start(context.Background(), &config.AgentContainer{
		Name:  "no-strategy-test",
		Image: "alpine",
	}, StartOptions{})
	require.NoError(t, err)
	assert.NotNil(t, session)
}

// ---------------------------------------------------------------------------
// parseComposePsOutput tests
// ---------------------------------------------------------------------------

func TestParseComposePsOutput_NDJSON(t *testing.T) {
	// Newline-delimited JSON (older docker compose versions).
	input := `{"ID":"abc123","Name":"myproject-web-1","Service":"web","State":"running","Image":"alpine:latest","CreatedAt":"2026-02-15 10:00:00 +0000 UTC"}
{"ID":"def456","Name":"myproject-db-1","Service":"db","State":"running","Image":"postgres:16","CreatedAt":"2026-02-15 10:00:01 +0000 UTC"}`

	entries, err := parseComposePsOutput(input)
	require.NoError(t, err)
	require.Len(t, entries, 2)

	assert.Equal(t, "abc123", entries[0].ID)
	assert.Equal(t, "myproject-web-1", entries[0].Name)
	assert.Equal(t, "web", entries[0].Service)
	assert.Equal(t, "running", entries[0].State)
	assert.Equal(t, "alpine:latest", entries[0].Image)

	assert.Equal(t, "def456", entries[1].ID)
	assert.Equal(t, "myproject-db-1", entries[1].Name)
	assert.Equal(t, "db", entries[1].Service)
	assert.Equal(t, "postgres:16", entries[1].Image)
}

func TestParseComposePsOutput_JSONArray(t *testing.T) {
	// JSON array (newer docker compose versions).
	input := `[{"ID":"abc123","Name":"myproject-web-1","Service":"web","State":"running","Image":"alpine:latest"},{"ID":"def456","Name":"myproject-db-1","Service":"db","State":"exited","Image":"postgres:16"}]`

	entries, err := parseComposePsOutput(input)
	require.NoError(t, err)
	require.Len(t, entries, 2)

	assert.Equal(t, "abc123", entries[0].ID)
	assert.Equal(t, "running", entries[0].State)
	assert.Equal(t, "def456", entries[1].ID)
	assert.Equal(t, "exited", entries[1].State)
}

func TestParseComposePsOutput_Empty(t *testing.T) {
	entries, err := parseComposePsOutput("")
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestParseComposePsOutput_SingleEntry(t *testing.T) {
	input := `{"ID":"abc123","Name":"myproject-web-1","Service":"web","State":"running","Image":"alpine:latest"}`

	entries, err := parseComposePsOutput(input)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "abc123", entries[0].ID)
}

func TestParseComposePsOutput_InvalidJSON(t *testing.T) {
	input := `not valid json`

	_, err := parseComposePsOutput(input)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parsing compose ps line")
}

func TestParseComposePsOutput_BlankLines(t *testing.T) {
	input := `{"ID":"abc123","Name":"web","Service":"web","State":"running","Image":"alpine"}

{"ID":"def456","Name":"db","Service":"db","State":"running","Image":"postgres"}
`

	entries, err := parseComposePsOutput(input)
	require.NoError(t, err)
	require.Len(t, entries, 2)
}

// ---------------------------------------------------------------------------
// ComposeRuntime.List tests (using faked exec)
// ---------------------------------------------------------------------------

// listExecFn returns an exec factory that responds to compose ps commands
// with the provided stdout content and optional exit error.
func listExecFn(stdout string, exitErr error) execCmdFactory {
	return func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if exitErr != nil {
			// Return a command that prints stdout to stderr and exits with error.
			return exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("echo %q >&2; exit 1", stdout))
		}
		if stdout == "" {
			return exec.CommandContext(ctx, "true")
		}
		return exec.CommandContext(ctx, "echo", "-n", stdout)
	}
}

func TestComposeRuntime_List_RunningContainers(t *testing.T) {
	jsonOutput := `{"ID":"abc123","Name":"myproject-web-1","Service":"web","State":"running","Image":"alpine:latest"}
{"ID":"def456","Name":"myproject-db-1","Service":"db","State":"running","Image":"postgres:16"}`

	rt, err := NewComposeRuntime(
		WithComposeLogger(zap.NewNop()),
		WithProjectName("myproject"),
		withExecFactory(listExecFn(jsonOutput, nil)),
	)
	require.NoError(t, err)

	sessions, err := rt.List(context.Background(), false)
	require.NoError(t, err)
	require.Len(t, sessions, 2)

	assert.Equal(t, "abc123", sessions[0].ContainerID)
	assert.Equal(t, "myproject-web-1", sessions[0].Name)
	assert.Equal(t, "alpine:latest", sessions[0].Image)
	assert.Equal(t, RuntimeCompose, sessions[0].RuntimeType)
	assert.Equal(t, "running", sessions[0].Status)

	assert.Equal(t, "def456", sessions[1].ContainerID)
	assert.Equal(t, "myproject-db-1", sessions[1].Name)
	assert.Equal(t, "postgres:16", sessions[1].Image)
	assert.Equal(t, RuntimeCompose, sessions[1].RuntimeType)
}

func TestComposeRuntime_List_AllIncludesStopped(t *testing.T) {
	jsonOutput := `{"ID":"abc123","Name":"myproject-web-1","Service":"web","State":"running","Image":"alpine:latest"}
{"ID":"def456","Name":"myproject-db-1","Service":"db","State":"exited","Image":"postgres:16"}`

	rt, err := NewComposeRuntime(
		WithComposeLogger(zap.NewNop()),
		WithProjectName("myproject"),
		withExecFactory(listExecFn(jsonOutput, nil)),
	)
	require.NoError(t, err)

	sessions, err := rt.List(context.Background(), true)
	require.NoError(t, err)
	require.Len(t, sessions, 2)

	assert.Equal(t, "running", sessions[0].Status)
	assert.Equal(t, "exited", sessions[1].Status)
}

func TestComposeRuntime_List_FilterNonRunning(t *testing.T) {
	// When all=false, if the compose CLI still returned non-running containers
	// (defensive filter), they should be excluded.
	jsonOutput := `{"ID":"abc123","Name":"web","Service":"web","State":"running","Image":"alpine"}
{"ID":"def456","Name":"db","Service":"db","State":"exited","Image":"postgres"}`

	rt, err := NewComposeRuntime(
		WithComposeLogger(zap.NewNop()),
		withExecFactory(listExecFn(jsonOutput, nil)),
	)
	require.NoError(t, err)

	sessions, err := rt.List(context.Background(), false)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, "abc123", sessions[0].ContainerID)
	assert.Equal(t, "running", sessions[0].Status)
}

func TestComposeRuntime_List_EmptyOutput(t *testing.T) {
	rt, err := NewComposeRuntime(
		WithComposeLogger(zap.NewNop()),
		withExecFactory(listExecFn("", nil)),
	)
	require.NoError(t, err)

	sessions, err := rt.List(context.Background(), false)
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

func TestComposeRuntime_List_ErrorPropagation(t *testing.T) {
	rt, err := NewComposeRuntime(
		WithComposeLogger(zap.NewNop()),
		withExecFactory(listExecFn("something went wrong", fmt.Errorf("exit status 1"))),
	)
	require.NoError(t, err)

	_, err = rt.List(context.Background(), false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "compose runtime: listing containers")
}

func TestComposeRuntime_List_PassesAllFlag(t *testing.T) {
	// Verify that -a flag is passed when all=true.
	var capturedArgs [][]string
	var mu sync.Mutex
	factory := func(ctx context.Context, name string, args ...string) *exec.Cmd {
		mu.Lock()
		capturedArgs = append(capturedArgs, append([]string{name}, args...))
		mu.Unlock()
		return exec.CommandContext(ctx, "true")
	}

	rt, err := NewComposeRuntime(
		WithComposeLogger(zap.NewNop()),
		WithProjectName("test"),
		withExecFactory(factory),
	)
	require.NoError(t, err)

	_, _ = rt.List(context.Background(), true)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, capturedArgs, 1)
	assert.Contains(t, capturedArgs[0], "-a")
	assert.Contains(t, capturedArgs[0], "--format")
	assert.Contains(t, capturedArgs[0], "json")
}

func TestComposeRuntime_List_NoAllFlagOmitsA(t *testing.T) {
	var capturedArgs [][]string
	var mu sync.Mutex
	factory := func(ctx context.Context, name string, args ...string) *exec.Cmd {
		mu.Lock()
		capturedArgs = append(capturedArgs, append([]string{name}, args...))
		mu.Unlock()
		return exec.CommandContext(ctx, "true")
	}

	rt, err := NewComposeRuntime(
		WithComposeLogger(zap.NewNop()),
		WithProjectName("test"),
		withExecFactory(factory),
	)
	require.NoError(t, err)

	_, _ = rt.List(context.Background(), false)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, capturedArgs, 1)
	assert.NotContains(t, capturedArgs[0], "-a")
}

func TestComposeRuntime_List_CreatedAtParsing(t *testing.T) {
	jsonOutput := `{"ID":"abc123","Name":"web","Service":"web","State":"running","Image":"alpine","CreatedAt":"2026-02-15 10:30:00 +0000 UTC"}`

	rt, err := NewComposeRuntime(
		WithComposeLogger(zap.NewNop()),
		withExecFactory(listExecFn(jsonOutput, nil)),
	)
	require.NoError(t, err)

	sessions, err := rt.List(context.Background(), true)
	require.NoError(t, err)
	require.Len(t, sessions, 1)

	expected := time.Date(2026, 2, 15, 10, 30, 0, 0, time.UTC)
	assert.Equal(t, expected, sessions[0].CreatedAt)
}

func TestComposeRuntime_List_InvalidCreatedAt(t *testing.T) {
	// Invalid CreatedAt should not cause an error; just use zero time.
	jsonOutput := `{"ID":"abc123","Name":"web","Service":"web","State":"running","Image":"alpine","CreatedAt":"not-a-date"}`

	rt, err := NewComposeRuntime(
		WithComposeLogger(zap.NewNop()),
		withExecFactory(listExecFn(jsonOutput, nil)),
	)
	require.NoError(t, err)

	sessions, err := rt.List(context.Background(), true)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.True(t, sessions[0].CreatedAt.IsZero())
}
