package container

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// ComposeProject represents a minimal docker-compose project structure.
type ComposeProject struct {
	Services map[string]ComposeService `yaml:"services"`
	Networks map[string]ComposeNetwork `yaml:"networks,omitempty"`
}

// ComposeService defines a single service in a Compose project.
type ComposeService struct {
	Image       string            `yaml:"image"`
	Command     []string          `yaml:"command,omitempty"`
	Environment map[string]string `yaml:"environment,omitempty"`
	Networks    []string          `yaml:"networks"`
	Tmpfs       []string          `yaml:"tmpfs,omitempty"`
	SecurityOpt []string          `yaml:"security_opt,omitempty"`
	ReadOnly    bool              `yaml:"read_only,omitempty"`
	CapDrop     []string          `yaml:"cap_drop,omitempty"`
}

// ComposeNetwork defines a Compose network.
type ComposeNetwork struct {
	Driver   string `yaml:"driver"`
	Internal bool   `yaml:"internal,omitempty"`
}

// RenderComposeProject generates a docker-compose project from the agent
// service definition and a set of MCP service configs. The agent service is
// connected to the MCP bridge network so it can reach sidecar MCP servers.
// Each MCP service is hardened with read-only rootfs, all capabilities dropped,
// no-new-privileges, and a tmpfs at /run/secrets.
func RenderComposeProject(agentService string, agentImage string, mcpServices []MCPServiceConfig, networkName string) (*ComposeProject, error) {
	if agentService == "" {
		return nil, fmt.Errorf("render compose: agent service name must not be empty")
	}
	if agentImage == "" {
		return nil, fmt.Errorf("render compose: agent image must not be empty")
	}
	if networkName == "" {
		return nil, fmt.Errorf("render compose: network name must not be empty")
	}

	project := &ComposeProject{
		Services: make(map[string]ComposeService),
		Networks: map[string]ComposeNetwork{
			networkName: {
				Driver: "bridge",
			},
		},
	}

	// Agent service — connected to the MCP bridge network.
	project.Services[agentService] = ComposeService{
		Image:    agentImage,
		Networks: []string{networkName},
	}

	// MCP sidecar services — isolated and hardened.
	for _, mcp := range mcpServices {
		svcName := fmt.Sprintf("mcp-%s", mcp.Name)

		svc := ComposeService{
			Image:       mcp.Image,
			Networks:    []string{networkName},
			ReadOnly:    true,
			CapDrop:     []string{"ALL"},
			SecurityOpt: []string{"no-new-privileges:true"},
			Tmpfs:       []string{"/run/secrets"},
		}

		if len(mcp.Command) > 0 {
			svc.Command = mcp.Command
		}
		if len(mcp.Environment) > 0 {
			svc.Environment = mcp.Environment
		}

		project.Services[svcName] = svc
	}

	return project, nil
}

// MarshalComposeProject serializes a ComposeProject to YAML bytes.
func MarshalComposeProject(p *ComposeProject) ([]byte, error) {
	data, err := yaml.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal compose project: %w", err)
	}
	return data, nil
}
