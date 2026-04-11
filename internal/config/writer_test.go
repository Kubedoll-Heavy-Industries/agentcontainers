package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPatchCapabilities_RoundTrip(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		caps            Capabilities
		wantShellBinary string
	}{
		{
			name: "replace existing capabilities",
			input: `{
  "name": "test",
  "image": "alpine:3",
  "agent": {
    "capabilities": {
      "shell": {
        "commands": [{"binary": "git"}]
      }
    }
  }
}`,
			caps: Capabilities{
				Shell: &ShellCaps{
					Commands: []ShellCommand{{Binary: "npm"}},
				},
			},
			wantShellBinary: "npm",
		},
		{
			name: "add capabilities to existing agent",
			input: `{
  "name": "test",
  "image": "alpine:3",
  "agent": {
    "policy": {"escalation": "pause"}
  }
}`,
			caps: Capabilities{
				Shell: &ShellCaps{
					Commands: []ShellCommand{{Binary: "go"}},
				},
			},
			wantShellBinary: "go",
		},
		{
			name: "add agent section when missing",
			input: `{
  "name": "test",
  "image": "alpine:3"
}`,
			caps: Capabilities{
				Shell: &ShellCaps{
					Commands: []ShellCommand{{Binary: "cargo"}},
				},
			},
			wantShellBinary: "cargo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := patchCapabilities([]byte(tt.input), &tt.caps)
			if err != nil {
				t.Fatalf("patchCapabilities() error: %v", err)
			}

			var cfg AgentContainer
			if err := json.Unmarshal(result, &cfg); err != nil {
				t.Fatalf("result is not valid JSON: %v\nresult:\n%s", err, string(result))
			}

			if cfg.Agent == nil {
				t.Fatal("Agent is nil after patching")
			}
			if cfg.Agent.Capabilities == nil {
				t.Fatal("Agent.Capabilities is nil after patching")
			}
			if cfg.Agent.Capabilities.Shell == nil {
				t.Fatal("Agent.Capabilities.Shell is nil after patching")
			}
			if len(cfg.Agent.Capabilities.Shell.Commands) == 0 {
				t.Fatal("Agent.Capabilities.Shell.Commands is empty after patching")
			}
			if got := cfg.Agent.Capabilities.Shell.Commands[0].Binary; got != tt.wantShellBinary {
				t.Errorf("Shell.Commands[0].Binary = %q, want %q", got, tt.wantShellBinary)
			}
		})
	}
}

func TestPatchCapabilities_CommentsPreserved(t *testing.T) {
	input := `// Top-level comment
{
  // Container name
  "name": "commented-container",
  "image": "node:22-bookworm", // inline comment
  "agent": {
    "capabilities": {
      "shell": {
        "commands": [
          // Allow git
          {"binary": "git"}
        ]
      }
    }
  }
}
`

	caps := Capabilities{
		Shell: &ShellCaps{
			Commands: []ShellCommand{{Binary: "npm"}},
		},
	}

	result, err := patchCapabilities([]byte(input), &caps)
	if err != nil {
		t.Fatalf("patchCapabilities() error: %v", err)
	}

	resultStr := string(result)

	if !strings.Contains(resultStr, "Top-level comment") {
		t.Error("top-level comment was not preserved")
	}
	if !strings.Contains(resultStr, "Container name") {
		t.Error("'Container name' comment was not preserved")
	}
	if !strings.Contains(resultStr, "inline comment") {
		t.Error("inline comment was not preserved")
	}
}

func TestPatchCapabilities_PreservesOtherFields(t *testing.T) {
	input := `{
  "name": "test",
  "image": "alpine:3",
  "agent": {
    "capabilities": {
      "shell": {"commands": [{"binary": "git"}]}
    },
    "policy": {
      "escalation": "pause",
      "auditLog": true
    }
  }
}`

	caps := Capabilities{
		Network: &NetworkCaps{
			Egress: []EgressRule{{Host: "example.com", Port: 443}},
		},
	}

	result, err := patchCapabilities([]byte(input), &caps)
	if err != nil {
		t.Fatalf("patchCapabilities() error: %v", err)
	}

	var cfg AgentContainer
	if err := json.Unmarshal(result, &cfg); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}

	if cfg.Agent == nil || cfg.Agent.Policy == nil {
		t.Fatal("Agent.Policy was lost during patching")
	}
	if cfg.Agent.Policy.Escalation != "pause" {
		t.Errorf("Policy.Escalation = %q, want %q", cfg.Agent.Policy.Escalation, "pause")
	}
	if !cfg.Agent.Policy.AuditLog {
		t.Error("Policy.AuditLog was lost during patching")
	}

	if cfg.Agent.Capabilities == nil || cfg.Agent.Capabilities.Network == nil {
		t.Fatal("Network capabilities missing after patching")
	}
	if len(cfg.Agent.Capabilities.Network.Egress) != 1 {
		t.Fatalf("len(Network.Egress) = %d, want 1", len(cfg.Agent.Capabilities.Network.Egress))
	}
	if cfg.Agent.Capabilities.Network.Egress[0].Host != "example.com" {
		t.Errorf("Egress[0].Host = %q, want %q", cfg.Agent.Capabilities.Network.Egress[0].Host, "example.com")
	}
}

func TestPatchCapabilities_InvalidInput(t *testing.T) {
	_, err := patchCapabilities([]byte(`{broken`), &Capabilities{})
	if err == nil {
		t.Fatal("expected error for invalid JSONC, got nil")
	}
	if !strings.Contains(err.Error(), "parsing JSONC") {
		t.Errorf("error = %v, want error containing %q", err, "parsing JSONC")
	}
}

func TestSaveCapabilities_FileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agentcontainer.json")

	initial := `{
  "name": "test",
  "image": "alpine:3",
  "agent": {
    "capabilities": {
      "shell": {"commands": [{"binary": "git"}]}
    }
  }
}`
	if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
		t.Fatalf("writing initial file: %v", err)
	}

	newCaps := &Capabilities{
		Shell: &ShellCaps{
			Commands: []ShellCommand{
				{Binary: "git"},
				{Binary: "npm"},
			},
		},
		Network: &NetworkCaps{
			Egress: []EgressRule{{Host: "registry.npmjs.org", Port: 443}},
		},
	}

	if err := SaveCapabilities(path, newCaps); err != nil {
		t.Fatalf("SaveCapabilities() error: %v", err)
	}

	cfg, err := parseFile(path)
	if err != nil {
		t.Fatalf("parseFile() after save: %v", err)
	}

	if cfg.Agent == nil || cfg.Agent.Capabilities == nil {
		t.Fatal("Agent.Capabilities is nil after save")
	}
	if got := len(cfg.Agent.Capabilities.Shell.Commands); got != 2 {
		t.Errorf("len(Shell.Commands) = %d, want 2", got)
	}
	if cfg.Agent.Capabilities.Network == nil {
		t.Fatal("Network is nil after save")
	}
	if got := len(cfg.Agent.Capabilities.Network.Egress); got != 1 {
		t.Errorf("len(Network.Egress) = %d, want 1", got)
	}
}

func TestSaveCapabilities_NonexistentFile(t *testing.T) {
	err := SaveCapabilities("/nonexistent/path/config.json", &Capabilities{})
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
	if !strings.Contains(err.Error(), "save: reading file") {
		t.Errorf("error = %v, want error containing %q", err, "save: reading file")
	}
}

func TestPatchCapabilities_FullCapabilities(t *testing.T) {
	input := `{"name": "test", "image": "alpine:3"}`

	caps := Capabilities{
		Filesystem: &FilesystemCaps{
			Read:  []string{"/workspace/**"},
			Write: []string{"/workspace/output/**"},
			Deny:  []string{"/workspace/.env"},
		},
		Network: &NetworkCaps{
			Egress: []EgressRule{
				{Host: "api.github.com", Port: 443, Protocol: "tcp"},
			},
			Deny: []string{"*.internal.corp"},
		},
		Shell: &ShellCaps{
			Commands: []ShellCommand{
				{Binary: "git", Subcommands: []string{"clone", "pull"}, DenyArgs: []string{"--force"}},
			},
		},
		Git: &GitCaps{
			Branches: &BranchCaps{
				Push: []string{"feature/*"},
				Deny: []string{"main"},
			},
		},
	}

	result, err := patchCapabilities([]byte(input), &caps)
	if err != nil {
		t.Fatalf("patchCapabilities() error: %v", err)
	}

	var cfg AgentContainer
	if err := json.Unmarshal(result, &cfg); err != nil {
		t.Fatalf("result is not valid JSON: %v\nresult:\n%s", err, string(result))
	}

	if cfg.Agent == nil || cfg.Agent.Capabilities == nil {
		t.Fatal("Agent.Capabilities is nil")
	}
	c := cfg.Agent.Capabilities

	if c.Filesystem == nil {
		t.Fatal("Filesystem is nil")
	}
	if len(c.Filesystem.Read) != 1 || c.Filesystem.Read[0] != "/workspace/**" {
		t.Errorf("Filesystem.Read = %v, want [/workspace/**]", c.Filesystem.Read)
	}

	if c.Network == nil {
		t.Fatal("Network is nil")
	}
	if len(c.Network.Egress) != 1 || c.Network.Egress[0].Host != "api.github.com" {
		t.Errorf("Network.Egress[0].Host = %q, want %q", c.Network.Egress[0].Host, "api.github.com")
	}

	if c.Shell == nil {
		t.Fatal("Shell is nil")
	}
	if len(c.Shell.Commands) != 1 || c.Shell.Commands[0].Binary != "git" {
		t.Errorf("Shell.Commands[0].Binary = %q, want %q", c.Shell.Commands[0].Binary, "git")
	}

	if c.Git == nil || c.Git.Branches == nil {
		t.Fatal("Git.Branches is nil")
	}
	if len(c.Git.Branches.Push) != 1 || c.Git.Branches.Push[0] != "feature/*" {
		t.Errorf("Git.Branches.Push = %v, want [feature/*]", c.Git.Branches.Push)
	}
}
