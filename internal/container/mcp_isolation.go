package container

import (
	"fmt"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

// MCPServiceConfig describes an isolated MCP server Compose service.
type MCPServiceConfig struct {
	// Name is the MCP server name from the config key.
	Name string

	// Image is the container image to run.
	Image string

	// Command overrides the default entrypoint command.
	Command []string

	// Environment holds extra environment variables for the service.
	Environment map[string]string

	// Secrets lists secret names to mount via tmpfs.
	Secrets []string

	// EgressRules lists allowed egress destinations (host:port or CIDR).
	EgressRules []string

	// NetworkName is the private bridge network this service connects to.
	NetworkName string
}

// GenerateMCPServices creates isolated Compose service definitions for each
// MCP server declared in the agent configuration. It returns the service
// configs, a private bridge network name, and any error.
//
// When no MCP servers are configured the function returns (nil, "", nil).
func GenerateMCPServices(cfg *config.AgentContainer, sessionID string) ([]MCPServiceConfig, string, error) {
	if cfg == nil || cfg.Agent == nil || cfg.Agent.Tools == nil || len(cfg.Agent.Tools.MCP) == 0 {
		return nil, "", nil
	}

	if sessionID == "" {
		return nil, "", fmt.Errorf("mcp isolation: sessionID must not be empty")
	}

	// Truncate sessionID to 8 characters for the network name.
	prefix := sessionID
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	networkName := fmt.Sprintf("ac-mcp-%s", prefix)

	// Build a set of declared secrets for quick lookup.
	declaredSecrets := make(map[string]struct{})
	if cfg.Agent.Secrets != nil {
		for name := range cfg.Agent.Secrets {
			declaredSecrets[name] = struct{}{}
		}
	}

	services := make([]MCPServiceConfig, 0, len(cfg.Agent.Tools.MCP))
	for name, mcp := range cfg.Agent.Tools.MCP {
		if mcp.Image == "" {
			return nil, "", fmt.Errorf("mcp isolation: MCP server %q has no image", name)
		}

		svc := MCPServiceConfig{
			Name:        name,
			Image:       mcp.Image,
			NetworkName: networkName,
		}

		// Resolve secrets: only include those that are declared in agent.secrets.
		for _, secretName := range mcp.Secrets {
			if _, ok := declaredSecrets[secretName]; ok {
				svc.Secrets = append(svc.Secrets, secretName)
			}
		}

		services = append(services, svc)
	}

	return services, networkName, nil
}
