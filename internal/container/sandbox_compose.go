package container

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

// sandboxComposeProjectPrefix is prepended to the VM name to form the Compose
// project name for MCP sidecars inside a sandbox VM.
const sandboxComposeProjectPrefix = "ac-mcp-"

// hasMCPContainerTools returns true if the agent config has at least one MCP
// tool of type "container" (or default/empty type, which implies "container").
func hasMCPContainerTools(cfg *config.AgentContainer) bool {
	if cfg == nil || cfg.Agent == nil || cfg.Agent.Tools == nil {
		return false
	}
	for _, mcp := range cfg.Agent.Tools.MCP {
		if mcp.Type == "" || mcp.Type == "container" {
			return true
		}
	}
	return false
}

// startMCPSidecars generates a Compose project from the agent config's MCP tool
// definitions, writes it to a temporary file, and launches the services inside
// the sandbox VM using the per-VM Docker socket.
//
// It returns the ComposeRuntime used to manage the sidecar lifecycle (for later
// teardown) and the Compose project name, or an error if setup fails.
func (s *SandboxRuntime) startMCPSidecars(ctx context.Context, cfg *config.AgentContainer, vmName, socketPath string) (*ComposeRuntime, string, error) {
	// Generate isolated MCP service configs from the agent configuration.
	mcpServices, networkName, err := GenerateMCPServices(cfg, vmName)
	if err != nil {
		return nil, "", fmt.Errorf("generating MCP services: %w", err)
	}
	if len(mcpServices) == 0 {
		return nil, "", nil
	}

	// Determine the agent image for the Compose project.
	agentImage := defaultTemplateImage
	if cfg.Image != "" {
		agentImage = cfg.Image
	}

	// Render the Compose project YAML.
	project, err := RenderComposeProject(vmName, agentImage, mcpServices, networkName)
	if err != nil {
		return nil, "", fmt.Errorf("rendering compose project: %w", err)
	}

	yamlBytes, err := MarshalComposeProject(project)
	if err != nil {
		return nil, "", fmt.Errorf("marshaling compose project: %w", err)
	}

	// Write the compose file to a temp directory.
	tmpDir, err := os.MkdirTemp("", "ac-sandbox-compose-*")
	if err != nil {
		return nil, "", fmt.Errorf("creating temp dir for compose file: %w", err)
	}

	composePath := filepath.Join(tmpDir, "compose.yml")
	if err := os.WriteFile(composePath, yamlBytes, 0600); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, "", fmt.Errorf("writing compose file: %w", err)
	}

	projectName := sandboxComposeProjectPrefix + vmName

	s.logger.Info("starting MCP sidecars in sandbox VM",
		zap.String("vm_name", vmName),
		zap.String("project", projectName),
		zap.Int("services", len(mcpServices)),
		zap.String("compose_file", composePath),
	)

	// Create a ComposeRuntime targeting the per-VM Docker daemon.
	dockerHost := "unix://" + socketPath
	composeRT, err := NewComposeRuntime(
		WithComposeLogger(s.logger.Named("compose")),
		WithProjectName(projectName),
		WithComposeFiles(composePath),
		WithProjectDir(tmpDir),
		WithDockerHost(dockerHost),
		WithComposeStopTimeout(10*time.Second),
	)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, "", fmt.Errorf("creating compose runtime: %w", err)
	}

	// Start the Compose project. We pass a minimal config and options since
	// the compose file is already fully rendered.
	_, err = composeRT.Start(ctx, &config.AgentContainer{
		Name:  projectName,
		Image: agentImage,
	}, StartOptions{
		WorkspacePath: tmpDir,
	})
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, "", fmt.Errorf("starting compose project: %w", err)
	}

	s.logger.Info("MCP sidecars started in sandbox VM",
		zap.String("vm_name", vmName),
		zap.String("project", projectName),
	)

	return composeRT, projectName, nil
}

// stopMCPSidecars tears down the Compose services for MCP sidecars inside a
// sandbox VM. It runs docker compose down and cleans up the temporary compose
// file directory.
func (s *SandboxRuntime) stopMCPSidecars(ctx context.Context, vmName string) {
	s.mu.Lock()
	composeRT := s.vmComposeRuntimes[vmName]
	delete(s.vmComposeRuntimes, vmName)
	s.mu.Unlock()

	if composeRT == nil {
		return
	}

	s.logger.Info("stopping MCP sidecars in sandbox VM", zap.String("vm_name", vmName))

	// Build a session with the project name as ContainerID (how ComposeRuntime
	// tracks projects).
	session := &Session{
		ContainerID: composeRT.projectName,
		RuntimeType: RuntimeCompose,
		Status:      "running",
	}

	if err := composeRT.Stop(ctx, session); err != nil {
		s.logger.Warn("failed to stop MCP sidecars",
			zap.String("vm_name", vmName),
			zap.Error(err),
		)
	}

	// Clean up the temp directory holding the compose file.
	if composeRT.projectDir != "" {
		if err := os.RemoveAll(composeRT.projectDir); err != nil {
			s.logger.Warn("failed to clean up compose temp dir",
				zap.String("dir", composeRT.projectDir),
				zap.Error(err),
			)
		}
	}
}
