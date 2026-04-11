package container

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/sandbox"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/sidecar"
)

// Compile-time checks that SandboxRuntime satisfies the Runtime and EventStreamer interfaces.
var _ Runtime = (*SandboxRuntime)(nil)
var _ EventStreamer = (*SandboxRuntime)(nil)

// vmNamePrefix is prepended to the agent config name to form the sandbox VM name.
const vmNamePrefix = "ac-"

// defaultTemplateImage is the Docker image used to create the agent container
// inside a sandbox VM. This matches what `docker sandbox create shell` uses.
const defaultTemplateImage = "docker/sandbox-templates:shell"

// SandboxAPI defines the sandbox client methods used by SandboxRuntime.
// The real sandbox.Client satisfies this interface; tests can substitute a mock.
type SandboxAPI interface {
	Health(ctx context.Context) (*sandbox.HealthResponse, error)
	CreateVM(ctx context.Context, req *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error)
	ListVMs(ctx context.Context) ([]sandbox.VMListEntry, error)
	InspectVM(ctx context.Context, name string) (*sandbox.VMInspectResponse, error)
	StopVM(ctx context.Context, name string) error
	DeleteVM(ctx context.Context, name string) error
	Keepalive(ctx context.Context, name string) error
	UpdateProxyConfig(ctx context.Context, req *sandbox.ProxyConfigRequest) error
}

// dockerClientFactory creates a Docker API client for a given host URL.
// This indirection allows tests to substitute a fake factory.
type dockerClientFactory func(host string) (client.APIClient, error)

// defaultDockerClientFactory creates a real Docker client connected to the
// given Unix socket via client.WithHost.
func defaultDockerClientFactory(host string) (client.APIClient, error) {
	return client.New(client.WithHost(host))
}

// sidecarStarterFunc is a function that starts a sidecar container.
// Defaults to sidecar.StartSidecar. Tests can override this.
type sidecarStarterFunc func(ctx context.Context, dockerClient client.APIClient, opts sidecar.StartOptions) (*sidecar.SidecarHandle, error)

// sidecarStopperFunc is a function that stops a sidecar container.
// Defaults to sidecar.StopSidecar. Tests can override this.
type sidecarStopperFunc func(ctx context.Context, dockerClient client.APIClient, handle *sidecar.SidecarHandle) error

// strategyFactory creates an enforcement.Strategy for a given gRPC target address.
// This indirection allows tests to substitute a mock strategy.
type strategyFactory func(target string) (enforcement.Strategy, error)

// defaultStrategyFactory creates a real gRPC enforcement strategy connected to
// the given target address using insecure transport.
func defaultStrategyFactory(target string) (enforcement.Strategy, error) {
	return enforcement.NewGRPCStrategy(target, enforcement.WithInsecure())
}

// SandboxRuntime implements the Runtime interface using Docker Sandbox microVMs
// for full agent isolation with a private Docker daemon. The agent runs inside
// a lightweight VM, preventing container escapes from reaching the host.
type SandboxRuntime struct {
	logger          *zap.Logger
	client          SandboxAPI
	dockerFactory   dockerClientFactory
	enfLevel        enforcement.Level
	sidecarStarter  sidecarStarterFunc
	sidecarStopper  sidecarStopperFunc
	strategyFactory strategyFactory

	mu                sync.Mutex
	vmDockerClients   map[string]client.APIClient       // per-VM Docker clients keyed by VM name
	vmSidecarHandles  map[string]*sidecar.SidecarHandle // per-VM sidecar handles
	vmStrategies      map[string]enforcement.Strategy   // per-VM enforcement strategies keyed by VMID
	vmAgentContainers map[string]string                 // VMID -> agent container ID inside VM
	vmComposeRuntimes map[string]*ComposeRuntime        // per-VM compose runtimes keyed by VM name
}

// SandboxOption configures a SandboxRuntime.
type SandboxOption func(*sandboxOptions)

type sandboxOptions struct {
	logger          *zap.Logger
	client          SandboxAPI
	dockerFactory   dockerClientFactory
	enfLevel        enforcement.Level
	sidecarStarter  sidecarStarterFunc
	sidecarStopper  sidecarStopperFunc
	strategyFactory strategyFactory
}

// WithSandboxLogger sets the logger for the Sandbox runtime.
func WithSandboxLogger(l *zap.Logger) SandboxOption {
	return func(o *sandboxOptions) {
		if l != nil {
			o.logger = l
		}
	}
}

// WithSandboxClient injects a SandboxAPI client (for testing or custom config).
func WithSandboxClient(c SandboxAPI) SandboxOption {
	return func(o *sandboxOptions) {
		if c != nil {
			o.client = c
		}
	}
}

// WithSandboxEnforcementLevel sets the enforcement level for the Sandbox runtime.
func WithSandboxEnforcementLevel(l enforcement.Level) SandboxOption {
	return func(o *sandboxOptions) {
		o.enfLevel = l
	}
}

// WithDockerClientFactory sets a custom factory for creating per-VM Docker
// clients. This is primarily useful for testing.
func WithDockerClientFactory(f dockerClientFactory) SandboxOption {
	return func(o *sandboxOptions) {
		if f != nil {
			o.dockerFactory = f
		}
	}
}

// WithSidecarStarter sets a custom function for starting the enforcer sidecar.
// This is primarily useful for testing.
func WithSidecarStarter(f sidecarStarterFunc) SandboxOption {
	return func(o *sandboxOptions) {
		if f != nil {
			o.sidecarStarter = f
		}
	}
}

// WithSidecarStopper sets a custom function for stopping the enforcer sidecar.
// This is primarily useful for testing.
func WithSidecarStopper(f sidecarStopperFunc) SandboxOption {
	return func(o *sandboxOptions) {
		if f != nil {
			o.sidecarStopper = f
		}
	}
}

// WithStrategyFactory sets a custom factory for creating per-VM enforcement
// strategies. This is primarily useful for testing.
func WithStrategyFactory(f strategyFactory) SandboxOption {
	return func(o *sandboxOptions) {
		if f != nil {
			o.strategyFactory = f
		}
	}
}

// NewSandboxRuntime creates a new Sandbox-backed Runtime. If no client is
// provided via WithSandboxClient, a default sandbox.Client is created that
// connects to the sandboxd Unix socket.
func NewSandboxRuntime(opts ...SandboxOption) (*SandboxRuntime, error) {
	o := &sandboxOptions{
		logger: zap.NewNop(),
	}
	for _, opt := range opts {
		opt(o)
	}

	if o.client == nil {
		c, err := sandbox.NewClient(sandbox.WithLogger(o.logger))
		if err != nil {
			return nil, fmt.Errorf("sandbox runtime: creating client: %w", err)
		}
		o.client = c
	}

	factory := o.dockerFactory
	if factory == nil {
		factory = defaultDockerClientFactory
	}

	starter := o.sidecarStarter
	if starter == nil {
		starter = sidecar.StartSidecar
	}

	stopper := o.sidecarStopper
	if stopper == nil {
		stopper = sidecar.StopSidecar
	}

	sf := o.strategyFactory
	if sf == nil {
		sf = defaultStrategyFactory
	}

	return &SandboxRuntime{
		logger:            o.logger,
		client:            o.client,
		dockerFactory:     factory,
		enfLevel:          o.enfLevel,
		sidecarStarter:    starter,
		sidecarStopper:    stopper,
		strategyFactory:   sf,
		vmDockerClients:   make(map[string]client.APIClient),
		vmSidecarHandles:  make(map[string]*sidecar.SidecarHandle),
		vmStrategies:      make(map[string]enforcement.Strategy),
		vmAgentContainers: make(map[string]string),
		vmComposeRuntimes: make(map[string]*ComposeRuntime),
	}, nil
}

// Start creates a new sandbox VM from the given agent configuration and returns
// a Session handle. The VM runs a private Docker daemon; its socket path is
// extracted from the CreateVM response and used to create a per-VM Docker client
// for subsequent Exec/Logs operations.
func (s *SandboxRuntime) Start(ctx context.Context, cfg *config.AgentContainer, opts StartOptions) (*Session, error) {
	vmName := vmNamePrefix + cfg.Name

	req := &sandbox.VMCreateRequest{
		AgentName:    "shell",
		WorkspaceDir: opts.WorkspacePath,
		VMName:       vmName,
	}

	// Wire resolved secrets into the VM as credential sources and service auth.
	if len(opts.ResolvedSecrets) > 0 {
		req.CredentialSources = buildCredentialSources(opts.ResolvedSecrets)
		req.ServiceAuthConfig = buildServiceAuthConfig(opts.ResolvedSecrets)
		s.logger.Info("wiring secrets to sandbox VM",
			zap.Int("credential_sources", len(req.CredentialSources)),
			zap.Int("service_auth_configs", len(req.ServiceAuthConfig)),
		)
	}

	s.logger.Info("creating sandbox VM",
		zap.String("vm_name", vmName),
		zap.String("workspace", opts.WorkspacePath),
	)

	resp, err := s.client.CreateVM(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("sandbox runtime: creating VM %s: %w", vmName, err)
	}

	socketPath := resp.VMConfig.SocketPath
	if socketPath == "" {
		return nil, fmt.Errorf("sandbox runtime: VM %s returned empty socket path", vmName)
	}

	s.logger.Info("sandbox VM created",
		zap.String("vm_id", resp.VMID),
		zap.String("vm_name", vmName),
		zap.String("socket", socketPath),
	)

	// Create a Docker client connected to the per-VM daemon socket.
	dockerCli, err := s.dockerFactory("unix://" + socketPath)
	if err != nil {
		// Best-effort cleanup: delete the VM we just created.
		if delErr := s.client.DeleteVM(ctx, vmName); delErr != nil {
			s.logger.Warn("failed to delete VM after docker client error",
				zap.String("vm_name", vmName),
				zap.Error(delErr),
			)
		}
		return nil, fmt.Errorf("sandbox runtime: creating docker client for VM %s: %w", vmName, err)
	}

	s.mu.Lock()
	s.vmDockerClients[vmName] = dockerCli
	s.mu.Unlock()

	// Pull the agent template image and create the agent container inside the VM.
	// The sandboxd API only creates the VM + Docker daemon; the agent container
	// must be created explicitly, matching what `docker sandbox create shell` does.
	templateImage := defaultTemplateImage
	if cfg.Image != "" {
		templateImage = cfg.Image
	}
	if err := s.ensureVMImage(ctx, dockerCli, vmName, templateImage); err != nil {
		_ = s.client.DeleteVM(ctx, vmName)
		return nil, fmt.Errorf("sandbox runtime: pulling template image in VM %s: %w", vmName, err)
	}

	var mounts []mount.Mount
	if opts.WorkspacePath != "" {
		mounts = append(mounts, mount.Mount{
			Type:   mount.TypeBind,
			Source: opts.WorkspacePath,
			Target: opts.WorkspacePath,
		})
	}

	// Forward proxy env vars from the VM creation response into the
	// agent container so processes inside see HTTP_PROXY, HTTPS_PROXY, etc.
	var env []string
	for k, v := range resp.ProxyEnvVars {
		env = append(env, k+"="+v)
	}

	createResp, err := dockerCli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config: &container.Config{
			Image: templateImage,
			Cmd:   []string{"sleep", "infinity"},
			Env:   env,
		},
		HostConfig: &container.HostConfig{
			Mounts: mounts,
		},
		Name: vmName,
	})
	if err != nil {
		_ = s.client.DeleteVM(ctx, vmName)
		return nil, fmt.Errorf("sandbox runtime: creating agent container in VM %s: %w", vmName, err)
	}

	if _, err := dockerCli.ContainerStart(ctx, createResp.ID, client.ContainerStartOptions{}); err != nil {
		_, _ = dockerCli.ContainerRemove(ctx, createResp.ID, client.ContainerRemoveOptions{Force: true})
		_ = s.client.DeleteVM(ctx, vmName)
		return nil, fmt.Errorf("sandbox runtime: starting agent container in VM %s: %w", vmName, err)
	}
	s.logger.Info("agent container started in VM",
		zap.String("vm_name", vmName),
		zap.String("container_id", createResp.ID),
		zap.String("image", templateImage),
	)

	// Inject the MITM proxy CA certificate into the container so TLS
	// verification works through the sandbox proxy. The cert is returned
	// as base64-encoded PEM in the VM creation response.
	if resp.CACertData != "" {
		if err := s.injectCACert(ctx, dockerCli, createResp.ID, vmName, resp.CACertData); err != nil {
			s.logger.Warn("failed to inject proxy CA cert into container",
				zap.String("vm_name", vmName),
				zap.Error(err),
			)
		}
	}

	// Push network proxy configuration if capabilities are defined.
	if cfg.Agent != nil && cfg.Agent.Capabilities != nil {
		proxyReq := sandbox.TranslatePolicy(vmName, cfg.Agent.Capabilities)
		s.logger.Info("pushing proxy config",
			zap.String("vm_name", vmName),
			zap.Int("allow_hosts", len(proxyReq.AllowHosts)),
			zap.Int("block_cidrs", len(proxyReq.BlockCIDRs)),
		)
		if err := s.client.UpdateProxyConfig(ctx, proxyReq); err != nil {
			s.logger.Warn("failed to push proxy config, VM created without network policy",
				zap.String("vm_name", vmName),
				zap.Error(err),
			)
			// Non-fatal: the VM is already running. Log the warning but continue.
			// The default proxy policy (from VM creation) still applies.
		}
	}

	// Start ac-enforcer sidecar inside VM if enforcement is enabled.
	var enforcerAddr string
	if s.enfLevel == enforcement.LevelGRPC {
		// Get VM IP for health checking from the host.
		vmInfo, inspectErr := s.client.InspectVM(ctx, vmName)
		if inspectErr != nil {
			s.logger.Warn("failed to inspect VM for enforcer setup",
				zap.String("vm_name", vmName),
				zap.Error(inspectErr),
			)
		} else if len(vmInfo.IPAddresses) == 0 {
			s.logger.Warn("VM has no IP addresses, skipping enforcer",
				zap.String("vm_name", vmName),
			)
		} else {
			vmIP := vmInfo.IPAddresses[0]
			enforcerAddr = fmt.Sprintf("%s:%d", vmIP, sidecar.DefaultPort)

			handle, startErr := s.sidecarStarter(ctx, dockerCli, sidecar.StartOptions{
				Required:        false, // non-fatal: VM works without enforcer
				HealthCheckAddr: enforcerAddr,
			})
			if startErr != nil {
				s.logger.Warn("failed to start enforcer in VM",
					zap.String("vm_name", vmName),
					zap.Error(startErr),
				)
				enforcerAddr = "" // clear since sidecar did not start
			} else if handle != nil {
				s.mu.Lock()
				s.vmSidecarHandles[vmName] = handle
				s.mu.Unlock()
				s.logger.Info("enforcer started in VM",
					zap.String("vm_name", vmName),
					zap.String("enforcer_addr", enforcerAddr),
				)

				// Create enforcement strategy connected to the in-VM enforcer.
				strategy, stratErr := s.strategyFactory(enforcerAddr)
				if stratErr != nil {
					s.logger.Warn("failed to create enforcement strategy",
						zap.String("vm_name", vmName),
						zap.Error(stratErr),
					)
				} else {
					// Find the agent container inside the VM to apply enforcement.
					agentContainerID, findErr := s.findAgentContainer(ctx, dockerCli, vmName)
					if findErr != nil {
						s.logger.Warn("failed to find agent container for enforcement",
							zap.String("vm_name", vmName),
							zap.Error(findErr),
						)
					} else {
						if applyErr := strategy.Apply(ctx, agentContainerID, 0, opts.Policy); applyErr != nil {
							s.logger.Warn("failed to apply enforcement policy",
								zap.String("vm_name", vmName),
								zap.String("container_id", agentContainerID),
								zap.Error(applyErr),
							)
						} else {
							s.logger.Info("enforcement applied in VM",
								zap.String("vm_name", vmName),
								zap.String("enforcer_addr", enforcerAddr),
							)
						}
						s.mu.Lock()
						s.vmAgentContainers[resp.VMID] = agentContainerID
						s.mu.Unlock()
					}
					s.mu.Lock()
					s.vmStrategies[resp.VMID] = strategy
					s.mu.Unlock()
				}
			} else {
				// handle == nil && err == nil means soft failure (Required: false)
				enforcerAddr = "" // clear since sidecar did not start
			}
		}
	}

	// Start MCP sidecar containers if the config declares container-type MCP tools.
	if hasMCPContainerTools(cfg) {
		composeRT, _, startErr := s.startMCPSidecars(ctx, cfg, vmName, socketPath)
		if startErr != nil {
			s.logger.Warn("failed to start MCP sidecars in VM",
				zap.String("vm_name", vmName),
				zap.Error(startErr),
			)
			// Non-fatal: the agent container is running, sidecars are optional.
		} else if composeRT != nil {
			s.mu.Lock()
			s.vmComposeRuntimes[vmName] = composeRT
			s.mu.Unlock()
		}
	}

	return &Session{
		ContainerID:  resp.VMID,
		Name:         vmName,
		RuntimeType:  RuntimeSandbox,
		Status:       "running",
		CreatedAt:    time.Now(),
		EnforcerAddr: enforcerAddr,
	}, nil
}

// Stop gracefully stops and deletes the sandbox VM. It first attempts to remove
// enforcement and stop the enforcer sidecar (if any), then the VM itself. If the
// graceful VM stop fails, it falls through to a forced delete.
func (s *SandboxRuntime) Stop(ctx context.Context, session *Session) error {
	if session == nil {
		return fmt.Errorf("sandbox runtime: nil session")
	}

	name := session.Name
	s.logger.Info("stopping sandbox VM", zap.String("name", name))

	// Remove enforcement strategy before stopping sidecar.
	s.mu.Lock()
	strategy := s.vmStrategies[session.ContainerID]
	agentContainerID := s.vmAgentContainers[session.ContainerID]
	delete(s.vmStrategies, session.ContainerID)
	delete(s.vmAgentContainers, session.ContainerID)
	s.mu.Unlock()

	if strategy != nil && agentContainerID != "" {
		if removeErr := strategy.Remove(ctx, agentContainerID); removeErr != nil {
			s.logger.Warn("failed to remove enforcement",
				zap.String("vm_name", name),
				zap.Error(removeErr),
			)
		}
	}
	// Close the gRPC connection held by the strategy to prevent leaks.
	if strategy != nil {
		if closer, ok := strategy.(interface{ Close() error }); ok {
			if closeErr := closer.Close(); closeErr != nil {
				s.logger.Warn("failed to close enforcement strategy",
					zap.String("vm_name", name),
					zap.Error(closeErr),
				)
			}
		}
	}

	// Stop MCP sidecar Compose services before stopping the enforcer/VM.
	s.stopMCPSidecars(ctx, name)

	// Stop enforcer sidecar before stopping VM.
	s.mu.Lock()
	sidecarHandle := s.vmSidecarHandles[name]
	delete(s.vmSidecarHandles, name)
	s.mu.Unlock()

	if sidecarHandle != nil {
		dockerCli, dockerErr := s.getVMDockerClient(name)
		if dockerErr == nil {
			if stopErr := s.sidecarStopper(ctx, dockerCli, sidecarHandle); stopErr != nil {
				s.logger.Warn("failed to stop enforcer in VM",
					zap.String("name", name),
					zap.Error(stopErr),
				)
			} else {
				s.logger.Info("enforcer stopped in VM", zap.String("name", name))
			}
		}
	}

	if err := s.client.StopVM(ctx, name); err != nil {
		s.logger.Warn("failed to stop VM, attempting delete",
			zap.String("name", name), zap.Error(err))
	}
	if err := s.client.DeleteVM(ctx, name); err != nil {
		return fmt.Errorf("sandbox runtime: deleting VM %s: %w", name, err)
	}

	s.mu.Lock()
	if cli, ok := s.vmDockerClients[name]; ok && cli != nil {
		_ = cli.Close()
	}
	delete(s.vmDockerClients, name)
	s.mu.Unlock()

	session.Status = "stopped"
	s.logger.Info("sandbox VM removed", zap.String("name", name))
	return nil
}

// EnforcementEvents returns the enforcement event channel for the given
// session, or nil if enforcement is not active.
func (s *SandboxRuntime) EnforcementEvents(containerID string) <-chan enforcement.Event {
	s.mu.Lock()
	strategy := s.vmStrategies[containerID]
	agentContainerID := s.vmAgentContainers[containerID]
	s.mu.Unlock()
	if strategy == nil || agentContainerID == "" {
		return nil
	}
	return strategy.Events(agentContainerID)
}

// Exec runs a command inside the agent container running within the sandbox VM.
// It locates the running container via the per-VM Docker client, then uses the
// Docker exec API to run the command and capture output.
func (s *SandboxRuntime) Exec(ctx context.Context, session *Session, cmd []string) (*ExecResult, error) {
	if session == nil {
		return nil, fmt.Errorf("sandbox runtime: nil session")
	}
	if len(cmd) == 0 {
		return nil, fmt.Errorf("sandbox runtime: empty command")
	}

	vmName := session.Name
	dockerCli, err := s.getVMDockerClient(vmName)
	if err != nil {
		return nil, err
	}

	containerID, err := s.findAgentContainer(ctx, dockerCli, vmName)
	if err != nil {
		return nil, err
	}

	execResp, err := dockerCli.ExecCreate(ctx, containerID, client.ExecCreateOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return nil, fmt.Errorf("sandbox runtime: creating exec in VM %s: %w", vmName, err)
	}

	attach, err := dockerCli.ExecAttach(ctx, execResp.ID, client.ExecAttachOptions{})
	if err != nil {
		return nil, fmt.Errorf("sandbox runtime: attaching exec in VM %s: %w", vmName, err)
	}
	defer attach.Close()

	var stdout, stderr bytes.Buffer
	if _, err := stdcopy.StdCopy(&stdout, &stderr, attach.Reader); err != nil {
		return nil, fmt.Errorf("sandbox runtime: reading exec output in VM %s: %w", vmName, err)
	}

	inspect, err := dockerCli.ExecInspect(ctx, execResp.ID, client.ExecInspectOptions{})
	if err != nil {
		return nil, fmt.Errorf("sandbox runtime: inspecting exec in VM %s: %w", vmName, err)
	}

	return &ExecResult{
		ExitCode: inspect.ExitCode,
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
	}, nil
}

// Logs returns a ReadCloser that streams the agent container's combined
// stdout/stderr from inside the sandbox VM.
func (s *SandboxRuntime) Logs(ctx context.Context, session *Session) (io.ReadCloser, error) {
	if session == nil {
		return nil, fmt.Errorf("sandbox runtime: nil session")
	}

	vmName := session.Name
	dockerCli, err := s.getVMDockerClient(vmName)
	if err != nil {
		return nil, err
	}

	containerID, err := s.findAgentContainer(ctx, dockerCli, vmName)
	if err != nil {
		return nil, err
	}

	reader, err := dockerCli.ContainerLogs(ctx, containerID, client.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
	})
	if err != nil {
		return nil, fmt.Errorf("sandbox runtime: streaming logs in VM %s: %w", vmName, err)
	}

	return reader, nil
}

// List returns all agentcontainer-managed sandbox VMs. VMs are identified by
// the "ac-" name prefix. When all is false, only running/active VMs are returned.
func (s *SandboxRuntime) List(ctx context.Context, all bool) ([]*Session, error) {
	vms, err := s.client.ListVMs(ctx)
	if err != nil {
		return nil, fmt.Errorf("sandbox runtime: listing VMs: %w", err)
	}

	var sessions []*Session
	for _, vm := range vms {
		if !strings.HasPrefix(vm.VMName, vmNamePrefix) {
			continue
		}
		if !all && vm.Status != "running" && !vm.Active {
			continue
		}
		var createdAt time.Time
		if vm.CreatedAt != "" {
			if t, err := time.Parse(time.RFC3339, vm.CreatedAt); err == nil {
				createdAt = t
			}
		}
		sessions = append(sessions, &Session{
			ContainerID: vm.VMID,
			Name:        vm.VMName,
			RuntimeType: RuntimeSandbox,
			Status:      vm.Status,
			CreatedAt:   createdAt,
		})
	}
	return sessions, nil
}

// getVMDockerClient retrieves the cached per-VM Docker client.
func (s *SandboxRuntime) getVMDockerClient(vmName string) (client.APIClient, error) {
	s.mu.Lock()
	dockerCli, ok := s.vmDockerClients[vmName]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("sandbox runtime: no docker client for VM %s", vmName)
	}
	return dockerCli, nil
}

// mcpSidecarPrefix is the name prefix used by MCP sidecar services created
// via docker compose inside a sandbox VM. Compose containers are named
// <project>-mcp-<service>-<n>, so the "-mcp-" infix distinguishes them from
// the primary agent container.
const mcpSidecarPrefix = "mcp-"

// findAgentContainer discovers the running agent container inside a sandbox VM
// by listing containers via the per-VM Docker client. It skips MCP sidecar
// containers (Compose service names containing "-mcp-") and returns the first
// running container that matches the VM name, or the first non-sidecar.
func (s *SandboxRuntime) findAgentContainer(ctx context.Context, dockerCli client.APIClient, vmName string) (string, error) {
	result, err := dockerCli.ContainerList(ctx, client.ContainerListOptions{All: false})
	if err != nil {
		return "", fmt.Errorf("sandbox runtime: listing containers in VM %s: %w", vmName, err)
	}

	// First pass: look for a container whose name matches the VM name exactly.
	for _, c := range result.Items {
		if c.State != container.StateRunning {
			continue
		}
		for _, name := range c.Names {
			// Docker prepends "/" to container names.
			trimmed := strings.TrimPrefix(name, "/")
			if trimmed == vmName {
				return c.ID, nil
			}
		}
	}

	// Second pass: return the first running container that is not an MCP sidecar.
	for _, c := range result.Items {
		if c.State != container.StateRunning {
			continue
		}
		if isMCPSidecar(c.Names) {
			continue
		}
		return c.ID, nil
	}
	return "", fmt.Errorf("sandbox runtime: no running container found in VM %s (all containers are MCP sidecars or stopped)", vmName)
}

// isMCPSidecar returns true if any of the container's names indicate it is an
// MCP sidecar container. Compose containers are named <project>-mcp-<name>-<n>,
// so we look for the "-mcp-" infix in the name.
func isMCPSidecar(names []string) bool {
	for _, name := range names {
		trimmed := strings.TrimPrefix(name, "/")
		if strings.Contains(trimmed, "-"+mcpSidecarPrefix) {
			return true
		}
	}
	return false
}

// ensureVMImage pulls the template image into the VM's Docker daemon if not
// already present. This mirrors DockerRuntime.ensureImage but operates against
// the per-VM Docker client.
func (s *SandboxRuntime) ensureVMImage(ctx context.Context, dockerCli client.APIClient, vmName, ref string) error {
	if _, err := dockerCli.ImageInspect(ctx, ref); err == nil {
		s.logger.Debug("template image already present in VM",
			zap.String("vm_name", vmName),
			zap.String("image", ref),
		)
		return nil
	}

	s.logger.Info("pulling template image into VM",
		zap.String("vm_name", vmName),
		zap.String("image", ref),
	)
	reader, err := dockerCli.ImagePull(ctx, ref, client.ImagePullOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()

	if _, err := io.Copy(io.Discard, reader); err != nil {
		return fmt.Errorf("reading pull response: %w", err)
	}
	return nil
}

// injectCACert decodes the base64-encoded PEM CA certificate from the VM
// creation response and copies it into the running container via the Docker
// CopyToContainer API (tar archive). Without this, HTTPS requests through
// the sandbox MITM proxy fail certificate verification.
func (s *SandboxRuntime) injectCACert(ctx context.Context, dockerCli client.APIClient, containerID, vmName, certB64 string) error {
	certPEM, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return fmt.Errorf("decoding CA cert: %w", err)
	}

	// Build a tar archive containing the cert at the expected path.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name: "proxy-ca.crt",
		Mode: 0644,
		Size: int64(len(certPEM)),
	}); err != nil {
		return fmt.Errorf("writing tar header: %w", err)
	}
	if _, err := tw.Write(certPEM); err != nil {
		return fmt.Errorf("writing tar body: %w", err)
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("closing tar: %w", err)
	}

	if _, err := dockerCli.CopyToContainer(ctx, containerID, client.CopyToContainerOptions{
		DestinationPath: "/usr/local/share/ca-certificates/",
		Content:         &buf,
	}); err != nil {
		return fmt.Errorf("copying CA cert to container: %w", err)
	}

	s.logger.Info("proxy CA cert injected into container",
		zap.String("vm_name", vmName),
		zap.Int("cert_bytes", len(certPEM)),
	)
	return nil
}
