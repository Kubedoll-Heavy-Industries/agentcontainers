package container

import (
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

// ---------------------------------------------------------------------------
// GenerateMCPServices tests
// ---------------------------------------------------------------------------

func TestGenerateMCPServices_NoMCP(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.AgentContainer
	}{
		{"nil config", nil},
		{"nil agent", &config.AgentContainer{}},
		{"nil tools", &config.AgentContainer{Agent: &config.AgentConfig{}}},
		{"empty MCP map", &config.AgentContainer{
			Agent: &config.AgentConfig{
				Tools: &config.ToolsConfig{MCP: map[string]config.MCPToolConfig{}},
			},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			services, network, err := GenerateMCPServices(tt.cfg, "abc12345")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if services != nil {
				t.Errorf("expected nil services, got %v", services)
			}
			if network != "" {
				t.Errorf("expected empty network, got %q", network)
			}
		})
	}
}

func TestGenerateMCPServices_SingleMCP(t *testing.T) {
	cfg := &config.AgentContainer{
		Agent: &config.AgentConfig{
			Tools: &config.ToolsConfig{
				MCP: map[string]config.MCPToolConfig{
					"postgres": {Image: "postgres:16"},
				},
			},
		},
	}

	services, network, err := GenerateMCPServices(cfg, "session123456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}

	svc := services[0]
	if svc.Name != "postgres" {
		t.Errorf("expected name %q, got %q", "postgres", svc.Name)
	}
	if svc.Image != "postgres:16" {
		t.Errorf("expected image %q, got %q", "postgres:16", svc.Image)
	}
	if svc.NetworkName != network {
		t.Errorf("service network %q != returned network %q", svc.NetworkName, network)
	}
}

func TestGenerateMCPServices_MultipleMCP(t *testing.T) {
	cfg := &config.AgentContainer{
		Agent: &config.AgentConfig{
			Tools: &config.ToolsConfig{
				MCP: map[string]config.MCPToolConfig{
					"redis":    {Image: "redis:7"},
					"postgres": {Image: "postgres:16"},
				},
			},
		},
	}

	services, _, err := GenerateMCPServices(cfg, "abcdefgh")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(services))
	}

	names := make([]string, len(services))
	for i, s := range services {
		names[i] = s.Name
	}
	sort.Strings(names)
	if names[0] != "postgres" || names[1] != "redis" {
		t.Errorf("unexpected service names: %v", names)
	}
}

func TestGenerateMCPServices_NetworkName(t *testing.T) {
	cfg := &config.AgentContainer{
		Agent: &config.AgentConfig{
			Tools: &config.ToolsConfig{
				MCP: map[string]config.MCPToolConfig{
					"svc": {Image: "nginx:latest"},
				},
			},
		},
	}

	tests := []struct {
		sessionID       string
		expectedNetwork string
	}{
		{"abcdefghijklmnop", "ac-mcp-abcdefgh"},
		{"short", "ac-mcp-short"},
		{"12345678", "ac-mcp-12345678"},
	}

	for _, tt := range tests {
		t.Run(tt.sessionID, func(t *testing.T) {
			_, network, err := GenerateMCPServices(cfg, tt.sessionID)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if network != tt.expectedNetwork {
				t.Errorf("expected network %q, got %q", tt.expectedNetwork, network)
			}
		})
	}
}

func TestGenerateMCPServices_EmptySessionID(t *testing.T) {
	cfg := &config.AgentContainer{
		Agent: &config.AgentConfig{
			Tools: &config.ToolsConfig{
				MCP: map[string]config.MCPToolConfig{
					"svc": {Image: "nginx:latest"},
				},
			},
		},
	}

	_, _, err := GenerateMCPServices(cfg, "")
	if err == nil {
		t.Fatal("expected error for empty sessionID")
	}
}

func TestGenerateMCPServices_MissingImage(t *testing.T) {
	cfg := &config.AgentContainer{
		Agent: &config.AgentConfig{
			Tools: &config.ToolsConfig{
				MCP: map[string]config.MCPToolConfig{
					"broken": {Image: ""},
				},
			},
		},
	}

	_, _, err := GenerateMCPServices(cfg, "session1")
	if err == nil {
		t.Fatal("expected error for empty image")
	}
	if !strings.Contains(err.Error(), "no image") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGenerateMCPServices_SecretsFiltered(t *testing.T) {
	cfg := &config.AgentContainer{
		Agent: &config.AgentConfig{
			Tools: &config.ToolsConfig{
				MCP: map[string]config.MCPToolConfig{
					"svc": {
						Image:   "nginx:latest",
						Secrets: []string{"db-password", "api-key", "nonexistent"},
					},
				},
			},
			Secrets: map[string]config.SecretConfig{
				"db-password": {Provider: "env"},
				"api-key":     {Provider: "vault"},
			},
		},
	}

	services, _, err := GenerateMCPServices(cfg, "session1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	svc := services[0]
	// Only "db-password" and "api-key" are declared; "nonexistent" is filtered out.
	if len(svc.Secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d: %v", len(svc.Secrets), svc.Secrets)
	}
}

// ---------------------------------------------------------------------------
// RenderComposeProject tests
// ---------------------------------------------------------------------------

func TestRenderComposeProject_SecurityDefaults(t *testing.T) {
	mcpServices := []MCPServiceConfig{
		{
			Name:        "redis",
			Image:       "redis:7",
			NetworkName: "ac-mcp-test1234",
		},
	}

	project, err := RenderComposeProject("agent", "ubuntu:22.04", mcpServices, "ac-mcp-test1234")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	svc, ok := project.Services["mcp-redis"]
	if !ok {
		t.Fatal("mcp-redis service not found")
	}

	if !svc.ReadOnly {
		t.Error("expected read_only to be true")
	}
	if len(svc.CapDrop) != 1 || svc.CapDrop[0] != "ALL" {
		t.Errorf("expected cap_drop [ALL], got %v", svc.CapDrop)
	}
	if len(svc.SecurityOpt) != 1 || svc.SecurityOpt[0] != "no-new-privileges:true" {
		t.Errorf("expected security_opt [no-new-privileges:true], got %v", svc.SecurityOpt)
	}
	if len(svc.Tmpfs) != 1 || svc.Tmpfs[0] != "/run/secrets" {
		t.Errorf("expected tmpfs [/run/secrets], got %v", svc.Tmpfs)
	}
}

func TestRenderComposeProject_AgentConnectedToNetwork(t *testing.T) {
	project, err := RenderComposeProject("agent", "ubuntu:22.04", nil, "ac-mcp-net")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	agentSvc, ok := project.Services["agent"]
	if !ok {
		t.Fatal("agent service not found")
	}

	found := false
	for _, n := range agentSvc.Networks {
		if n == "ac-mcp-net" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("agent service not connected to network ac-mcp-net: %v", agentSvc.Networks)
	}
}

func TestRenderComposeProject_MCPIsolation(t *testing.T) {
	mcpServices := []MCPServiceConfig{
		{Name: "svc1", Image: "img1:latest", NetworkName: "ac-mcp-net"},
		{Name: "svc2", Image: "img2:latest", NetworkName: "ac-mcp-net"},
	}

	project, err := RenderComposeProject("agent", "ubuntu:22.04", mcpServices, "ac-mcp-net")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, name := range []string{"mcp-svc1", "mcp-svc2"} {
		svc, ok := project.Services[name]
		if !ok {
			t.Errorf("service %q not found", name)
			continue
		}
		// Each MCP service should only be on the bridge network.
		if len(svc.Networks) != 1 || svc.Networks[0] != "ac-mcp-net" {
			t.Errorf("service %q expected networks [ac-mcp-net], got %v", name, svc.Networks)
		}
	}

	// Network should exist.
	net, ok := project.Networks["ac-mcp-net"]
	if !ok {
		t.Fatal("network ac-mcp-net not found in project")
	}
	if net.Driver != "bridge" {
		t.Errorf("expected bridge driver, got %q", net.Driver)
	}
}

func TestRenderComposeProject_ValidationErrors(t *testing.T) {
	tests := []struct {
		name         string
		agentService string
		agentImage   string
		networkName  string
		wantErr      string
	}{
		{"empty agent service", "", "img", "net", "agent service name"},
		{"empty agent image", "svc", "", "net", "agent image"},
		{"empty network", "svc", "img", "", "network name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RenderComposeProject(tt.agentService, tt.agentImage, nil, tt.networkName)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestComposeProjectYAML(t *testing.T) {
	mcpServices := []MCPServiceConfig{
		{
			Name:        "mcp-server",
			Image:       "ghcr.io/example/mcp:v1",
			NetworkName: "ac-mcp-abcdefgh",
			Command:     []string{"serve", "--port", "8080"},
			Environment: map[string]string{"LOG_LEVEL": "debug"},
		},
	}

	project, err := RenderComposeProject("agent", "ubuntu:22.04", mcpServices, "ac-mcp-abcdefgh")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := MarshalComposeProject(project)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	// Parse back and verify structure.
	var parsed ComposeProject
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal roundtrip error: %v", err)
	}

	// Verify agent service exists.
	if _, ok := parsed.Services["agent"]; !ok {
		t.Error("agent service missing after roundtrip")
	}

	// Verify MCP service exists with expected image.
	mcpSvc, ok := parsed.Services["mcp-mcp-server"]
	if !ok {
		t.Fatal("mcp-mcp-server service missing after roundtrip")
	}
	if mcpSvc.Image != "ghcr.io/example/mcp:v1" {
		t.Errorf("expected image %q, got %q", "ghcr.io/example/mcp:v1", mcpSvc.Image)
	}
	if !mcpSvc.ReadOnly {
		t.Error("expected read_only after roundtrip")
	}
	if len(mcpSvc.Command) != 3 {
		t.Errorf("expected 3 command elements, got %d", len(mcpSvc.Command))
	}
	if mcpSvc.Environment["LOG_LEVEL"] != "debug" {
		t.Error("expected LOG_LEVEL=debug in environment")
	}

	// Verify network exists.
	net, ok := parsed.Networks["ac-mcp-abcdefgh"]
	if !ok {
		t.Fatal("network ac-mcp-abcdefgh missing after roundtrip")
	}
	if net.Driver != "bridge" {
		t.Errorf("expected bridge driver, got %q", net.Driver)
	}
}

func TestRenderComposeProject_MCPCommandAndEnv(t *testing.T) {
	mcpServices := []MCPServiceConfig{
		{
			Name:        "tool",
			Image:       "tool:v1",
			Command:     []string{"run", "--flag"},
			Environment: map[string]string{"KEY": "val"},
			NetworkName: "ac-mcp-net",
		},
	}

	project, err := RenderComposeProject("agent", "ubuntu:22.04", mcpServices, "ac-mcp-net")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	svc := project.Services["mcp-tool"]
	if len(svc.Command) != 2 || svc.Command[0] != "run" {
		t.Errorf("unexpected command: %v", svc.Command)
	}
	if svc.Environment["KEY"] != "val" {
		t.Errorf("unexpected env: %v", svc.Environment)
	}
}

func TestRenderComposeProject_MismatchedNetworkName(t *testing.T) {
	// MCPServiceConfig has a different NetworkName than the project-level
	// networkName. RenderComposeProject should use the project-level name
	// for all services, not the per-service field.
	mcpServices := []MCPServiceConfig{
		{
			Name:        "redis",
			Image:       "redis:7",
			NetworkName: "wrong-network",
		},
	}

	project, err := RenderComposeProject("agent", "ubuntu:22.04", mcpServices, "ac-mcp-correct")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	svc := project.Services["mcp-redis"]
	if len(svc.Networks) != 1 || svc.Networks[0] != "ac-mcp-correct" {
		t.Errorf("MCP service should use project networkName, got %v", svc.Networks)
	}

	// Verify the project declares the correct network.
	if _, ok := project.Networks["ac-mcp-correct"]; !ok {
		t.Error("expected project to declare ac-mcp-correct network")
	}
}

func TestRenderComposeProject_NoMCPServices(t *testing.T) {
	project, err := RenderComposeProject("agent", "ubuntu:22.04", nil, "ac-mcp-net")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(project.Services) != 1 {
		t.Errorf("expected 1 service (agent only), got %d", len(project.Services))
	}
	if _, ok := project.Services["agent"]; !ok {
		t.Error("agent service not found")
	}
}
