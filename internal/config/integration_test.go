//go:build integration

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfig_JSONCRoundTrip_Integration(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agentcontainer.json")

	// Write JSONC with comments and trailing commas.
	initial := `{
  // Project name
  "name": "roundtrip-test",
  "image": "alpine:3.19",
  /* Agent configuration */
  "agent": {
    "capabilities": {
      "shell": {
        "commands": [
          {"binary": "git"},
        ]
      }
    },
    "policy": {
      "escalation": "prompt",
      "sessionTimeout": "4h"
    }
  },
}`

	if err := os.WriteFile(cfgPath, []byte(initial), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	// Parse.
	cfg, err := ParseFile(cfgPath)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	if cfg.Name != "roundtrip-test" {
		t.Errorf("name = %q, want %q", cfg.Name, "roundtrip-test")
	}
	if cfg.Agent == nil || cfg.Agent.Capabilities == nil || cfg.Agent.Capabilities.Shell == nil {
		t.Fatal("expected shell capabilities to be parsed")
	}
	if len(cfg.Agent.Capabilities.Shell.Commands) != 1 || cfg.Agent.Capabilities.Shell.Commands[0].Binary != "git" {
		t.Errorf("shell commands = %+v, want [{Binary: git}]", cfg.Agent.Capabilities.Shell.Commands)
	}

	// Modify capabilities and save.
	cfg.Agent.Capabilities.Shell.Commands = append(cfg.Agent.Capabilities.Shell.Commands,
		ShellCommand{Binary: "npm"},
	)

	if err := SaveCapabilities(cfgPath, cfg.Agent.Capabilities); err != nil {
		t.Fatalf("SaveCapabilities: %v", err)
	}

	// Re-parse and verify.
	cfg2, err := ParseFile(cfgPath)
	if err != nil {
		t.Fatalf("re-parsing config: %v", err)
	}

	if cfg2.Agent == nil || cfg2.Agent.Capabilities == nil || cfg2.Agent.Capabilities.Shell == nil {
		t.Fatal("expected shell capabilities after save")
	}
	if len(cfg2.Agent.Capabilities.Shell.Commands) != 2 {
		t.Fatalf("expected 2 shell commands, got %d", len(cfg2.Agent.Capabilities.Shell.Commands))
	}
	if cfg2.Agent.Capabilities.Shell.Commands[1].Binary != "npm" {
		t.Errorf("second command binary = %q, want %q", cfg2.Agent.Capabilities.Shell.Commands[1].Binary, "npm")
	}

	// Verify the file is still valid JSON.
	if _, err := ParseFile(cfgPath); err != nil {
		t.Errorf("saved file is not valid: %v", err)
	}
}

func TestConfig_LoadResolution_Integration(t *testing.T) {
	tests := []struct {
		name    string
		layout  map[string]string // relative path -> content
		wantCfg string            // expected config name
	}{
		{
			name: "root agentcontainer.json",
			layout: map[string]string{
				"agentcontainer.json": `{"name": "root", "image": "alpine:3"}`,
			},
			wantCfg: "root",
		},
		{
			name: "devcontainer directory",
			layout: map[string]string{
				".devcontainer/agentcontainer.json": `{"name": "devcontainer-dir", "image": "alpine:3"}`,
			},
			wantCfg: "devcontainer-dir",
		},
		{
			name: "plain devcontainer.json",
			layout: map[string]string{
				".devcontainer/devcontainer.json": `{"name": "plain-dc", "image": "alpine:3"}`,
			},
			wantCfg: "plain-dc",
		},
		{
			name: "root takes priority over devcontainer",
			layout: map[string]string{
				"agentcontainer.json":               `{"name": "root-wins", "image": "alpine:3"}`,
				".devcontainer/agentcontainer.json": `{"name": "should-not-load", "image": "alpine:3"}`,
			},
			wantCfg: "root-wins",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for relPath, content := range tt.layout {
				fullPath := filepath.Join(dir, relPath)
				if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
					t.Fatalf("creating dirs: %v", err)
				}
				if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
					t.Fatalf("writing %s: %v", relPath, err)
				}
			}

			cfg, _, err := Load(dir)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Name != tt.wantCfg {
				t.Errorf("name = %q, want %q", cfg.Name, tt.wantCfg)
			}
		})
	}
}

func TestConfig_SaveToNewAgent_Integration(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agentcontainer.json")

	// Config with no agent key.
	initial := `{"name": "no-agent", "image": "alpine:3"}`
	if err := os.WriteFile(cfgPath, []byte(initial), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	caps := &Capabilities{
		Shell: &ShellCaps{
			Commands: []ShellCommand{{Binary: "git"}},
		},
	}

	if err := SaveCapabilities(cfgPath, caps); err != nil {
		t.Fatalf("SaveCapabilities: %v", err)
	}

	cfg, err := ParseFile(cfgPath)
	if err != nil {
		t.Fatalf("re-parsing: %v", err)
	}

	if cfg.Agent == nil || cfg.Agent.Capabilities == nil {
		t.Fatal("expected agent.capabilities after save")
	}
	if cfg.Agent.Capabilities.Shell == nil || len(cfg.Agent.Capabilities.Shell.Commands) == 0 {
		t.Fatal("expected shell commands after save")
	}
	if cfg.Agent.Capabilities.Shell.Commands[0].Binary != "git" {
		t.Errorf("binary = %q, want %q", cfg.Agent.Capabilities.Shell.Commands[0].Binary, "git")
	}
}

func TestConfig_FilePermissionsPreserved_Integration(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agentcontainer.json")

	initial := `{"name": "perms-test", "image": "alpine:3"}`
	if err := os.WriteFile(cfgPath, []byte(initial), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	caps := &Capabilities{
		Shell: &ShellCaps{
			Commands: []ShellCommand{{Binary: "echo"}},
		},
	}

	if err := SaveCapabilities(cfgPath, caps); err != nil {
		t.Fatalf("SaveCapabilities: %v", err)
	}

	info, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("permissions = %o, want 0600", info.Mode().Perm())
	}
}
