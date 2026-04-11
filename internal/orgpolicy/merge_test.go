package orgpolicy

import (
	"strings"
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

func TestMergePolicy(t *testing.T) {
	tests := []struct {
		name        string
		org         *OrgPolicy
		workspace   *config.AgentContainer
		wantErr     bool
		errContains string
	}{
		{
			name:      "nil org policy allows everything",
			org:       nil,
			workspace: &config.AgentContainer{Image: "ubuntu:22.04"},
			wantErr:   false,
		},
		{
			name:      "nil workspace is valid",
			org:       &OrgPolicy{AllowedCapabilities: []string{"filesystem"}},
			workspace: nil,
			wantErr:   false,
		},
		{
			name: "default policy allows all capabilities",
			org:  DefaultPolicy(),
			workspace: &config.AgentContainer{
				Image: "ubuntu:22.04",
				Agent: &config.AgentConfig{
					Capabilities: &config.Capabilities{
						Filesystem: &config.FilesystemCaps{Read: []string{"/data"}},
						Network:    &config.NetworkCaps{Egress: []config.EgressRule{{Host: "example.com"}}},
						Shell:      &config.ShellCaps{Commands: []config.ShellCommand{{Binary: "git"}}},
						Git:        &config.GitCaps{},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "workspace within allowed capabilities",
			org: &OrgPolicy{
				AllowedCapabilities: []string{"filesystem", "network", "shell", "git"},
			},
			workspace: &config.AgentContainer{
				Image: "ubuntu:22.04",
				Agent: &config.AgentConfig{
					Capabilities: &config.Capabilities{
						Filesystem: &config.FilesystemCaps{Read: []string{"/data"}},
						Shell:      &config.ShellCaps{Commands: []config.ShellCommand{{Binary: "make"}}},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "capability not in allowed list",
			org: &OrgPolicy{
				AllowedCapabilities: []string{"filesystem"},
			},
			workspace: &config.AgentContainer{
				Image: "ubuntu:22.04",
				Agent: &config.AgentConfig{
					Capabilities: &config.Capabilities{
						Filesystem: &config.FilesystemCaps{Read: []string{"/data"}},
						Network:    &config.NetworkCaps{Egress: []config.EgressRule{{Host: "example.com"}}},
					},
				},
			},
			wantErr:     true,
			errContains: `"network" is not allowed`,
		},
		{
			name: "multiple capabilities not in allowed list",
			org: &OrgPolicy{
				AllowedCapabilities: []string{"filesystem"},
			},
			workspace: &config.AgentContainer{
				Image: "ubuntu:22.04",
				Agent: &config.AgentConfig{
					Capabilities: &config.Capabilities{
						Network: &config.NetworkCaps{Egress: []config.EgressRule{{Host: "example.com"}}},
						Shell:   &config.ShellCaps{Commands: []config.ShellCommand{{Binary: "bash"}}},
					},
				},
			},
			wantErr:     true,
			errContains: "not allowed",
		},
		{
			name: "capability in denied list",
			org: &OrgPolicy{
				DeniedCapabilities: []string{"shell"},
			},
			workspace: &config.AgentContainer{
				Image: "ubuntu:22.04",
				Agent: &config.AgentConfig{
					Capabilities: &config.Capabilities{
						Shell: &config.ShellCaps{Commands: []config.ShellCommand{{Binary: "bash"}}},
					},
				},
			},
			wantErr:     true,
			errContains: `"shell" is denied`,
		},
		{
			name: "deny wins over allow",
			org: &OrgPolicy{
				AllowedCapabilities: []string{"shell", "git"},
				DeniedCapabilities:  []string{"shell"},
			},
			workspace: &config.AgentContainer{
				Image: "ubuntu:22.04",
				Agent: &config.AgentConfig{
					Capabilities: &config.Capabilities{
						Shell: &config.ShellCaps{Commands: []config.ShellCommand{{Binary: "bash"}}},
					},
				},
			},
			wantErr:     true,
			errContains: `"shell" is denied`,
		},
		{
			name: "workspace with no agent config passes",
			org: &OrgPolicy{
				AllowedCapabilities: []string{"filesystem"},
				DeniedCapabilities:  []string{"shell"},
			},
			workspace: &config.AgentContainer{
				Image: "ubuntu:22.04",
			},
			wantErr: false,
		},
		{
			name: "workspace with nil capabilities passes",
			org: &OrgPolicy{
				AllowedCapabilities: []string{"filesystem"},
			},
			workspace: &config.AgentContainer{
				Image: "ubuntu:22.04",
				Agent: &config.AgentConfig{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := MergePolicy(tt.org, tt.workspace)
			if tt.wantErr {
				if err == nil {
					t.Fatal("MergePolicy() error = nil, want error")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("MergePolicy() error = %q, want error containing %q", err.Error(), tt.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("MergePolicy() error = %v", err)
			}
		})
	}
}

func TestMergePolicy_AllowedMCPImages(t *testing.T) {
	tests := []struct {
		name      string
		policy    *OrgPolicy
		workspace *config.AgentContainer
		wantErr   bool
	}{
		{
			name:   "no allowlist permits all",
			policy: &OrgPolicy{},
			workspace: &config.AgentContainer{
				Agent: &config.AgentConfig{
					Tools: &config.ToolsConfig{
						MCP: map[string]config.MCPToolConfig{
							"server": {Image: "ghcr.io/any/image:v1"},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "allowed image passes",
			policy: &OrgPolicy{
				AllowedMCPImages: []string{"ghcr.io/myorg/approved:v1"},
			},
			workspace: &config.AgentContainer{
				Agent: &config.AgentConfig{
					Tools: &config.ToolsConfig{
						MCP: map[string]config.MCPToolConfig{
							"server": {Image: "ghcr.io/myorg/approved:v1"},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "disallowed image fails",
			policy: &OrgPolicy{
				AllowedMCPImages: []string{"ghcr.io/myorg/approved:v1"},
			},
			workspace: &config.AgentContainer{
				Agent: &config.AgentConfig{
					Tools: &config.ToolsConfig{
						MCP: map[string]config.MCPToolConfig{
							"server": {Image: "ghcr.io/evil/image:v1"},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "namespace prefix allows",
			policy: &OrgPolicy{
				AllowedMCPImages: []string{"ghcr.io/myorg/tools/"},
			},
			workspace: &config.AgentContainer{
				Agent: &config.AgentConfig{
					Tools: &config.ToolsConfig{
						MCP: map[string]config.MCPToolConfig{
							"server": {Image: "ghcr.io/myorg/tools/server:v1"},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:      "nil agent config is fine",
			policy:    &OrgPolicy{AllowedMCPImages: []string{"ghcr.io/x:v1"}},
			workspace: &config.AgentContainer{},
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := MergePolicy(tt.policy, tt.workspace)
			if (err != nil) != tt.wantErr {
				t.Errorf("MergePolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMergePolicy_MultipleViolations(t *testing.T) {
	org := &OrgPolicy{
		AllowedCapabilities: []string{"filesystem"},
		DeniedCapabilities:  []string{"git"},
	}
	ws := &config.AgentContainer{
		Image: "ubuntu:22.04",
		Agent: &config.AgentConfig{
			Capabilities: &config.Capabilities{
				Network: &config.NetworkCaps{Egress: []config.EgressRule{{Host: "example.com"}}},
				Shell:   &config.ShellCaps{Commands: []config.ShellCommand{{Binary: "bash"}}},
				Git:     &config.GitCaps{},
			},
		},
	}

	err := MergePolicy(org, ws)
	if err == nil {
		t.Fatal("MergePolicy() error = nil, want multiple violations")
	}

	errStr := err.Error()
	// Should contain violations for network (not allowed), shell (not allowed), and git (denied).
	if !strings.Contains(errStr, "network") {
		t.Errorf("error should mention network, got: %s", errStr)
	}
	if !strings.Contains(errStr, "shell") {
		t.Errorf("error should mention shell, got: %s", errStr)
	}
	if !strings.Contains(errStr, "git") {
		t.Errorf("error should mention git, got: %s", errStr)
	}
}
