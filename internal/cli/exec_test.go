package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/secrets"
)

func TestExecFlagParsing(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "no args",
			args:    []string{"exec"},
			wantErr: "requires at least 1 arg(s)",
		},
		{
			name:    "container id only",
			args:    []string{"exec", "abc123"},
			wantErr: "no command specified",
		},
		{
			name:    "unknown runtime",
			args:    []string{"exec", "--runtime", "podman", "abc123", "--", "ls"},
			wantErr: "unknown runtime",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newRootCmd("test", "abc", "now")
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestExecRequiresConfig(t *testing.T) {
	// When no config file exists, exec should fail because the approval
	// broker cannot determine what commands are allowed.
	tmp := t.TempDir()
	origDir, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origDir) }()

	cmd := newRootCmd("test", "abc", "now")
	cmd.SetArgs([]string{"exec", "abc123", "--", "ls"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when no config file exists")
	}
	if !strings.Contains(err.Error(), "no agentcontainer.json") {
		t.Errorf("expected config-not-found error, got: %v", err)
	}
}

func TestExecBrokerBlocksInterpreterFlags(t *testing.T) {
	// The approval broker should deny interpreter -c/-e flags.
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "agentcontainer.json")
	cfg := `{
		"name": "test",
		"image": "ubuntu",
		"agent": {
			"capabilities": {
				"shell": {
					"commands": [{"binary": "bash"}]
				}
			}
		}
	}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	cmd.SetArgs([]string{"exec", "--config", cfgPath, "abc123", "--", "bash", "-c", "echo pwned"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for interpreter with -c flag")
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Errorf("expected denial error, got: %v", err)
	}
}

func TestExecRuntimeDefault(t *testing.T) {
	cmd := newExecCmd()
	if err := cmd.ParseFlags([]string{"abc123", "--", "ls"}); err != nil {
		t.Fatalf("unexpected error parsing flags: %v", err)
	}

	runtimeVal, err := cmd.Flags().GetString("runtime")
	if err != nil {
		t.Fatalf("unexpected error getting runtime flag: %v", err)
	}
	if runtimeVal != "docker" {
		t.Errorf("expected default runtime %q, got %q", "docker", runtimeVal)
	}
}

func TestResolveSecretOnDemand_EnvProvider(t *testing.T) {
	t.Setenv("MY_TEST_SECRET", "supersecret")

	ref := secrets.SecretRef{
		Name:     "test-secret",
		Provider: "env",
		Params:   map[string]string{"env_var": "MY_TEST_SECRET"},
	}

	secret, err := resolveSecretOnDemand(context.Background(), ref)
	if err != nil {
		t.Fatalf("resolveSecretOnDemand() error = %v", err)
	}
	if string(secret.Value) != "supersecret" {
		t.Errorf("Value = %q, want %q", secret.Value, "supersecret")
	}
}

func TestResolveSecretOnDemand_UnsupportedProvider(t *testing.T) {
	ref := secrets.SecretRef{
		Name:     "test",
		Provider: "nonexistent-provider",
		Params:   map[string]string{},
	}

	_, err := resolveSecretOnDemand(context.Background(), ref)
	if err == nil {
		t.Fatal("expected error for unsupported provider")
	}
	if !strings.Contains(err.Error(), "unsupported provider") {
		t.Errorf("error = %q, want contains 'unsupported provider'", err.Error())
	}
}

func TestResolveSecretOnDemand_VaultEnvVars(t *testing.T) {
	// Verify that VAULT_ADDR and VAULT_TOKEN env vars are wired through.
	// We don't actually connect to Vault; just confirm no panic and expected error type.
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:18200")
	t.Setenv("VAULT_TOKEN", "test-token")

	ref := secrets.SecretRef{
		Name:     "my-secret",
		Provider: "vault",
		Params:   map[string]string{"path": "myapp/config"},
	}

	// The request will fail (no Vault server), but the provider must be wired correctly.
	_, err := resolveSecretOnDemand(context.Background(), ref)
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
	// Should not be "unsupported provider" — that would indicate wrong routing.
	if strings.Contains(err.Error(), "unsupported provider") {
		t.Errorf("vault provider should be supported, got: %v", err)
	}
}

func TestResolveSecretOnDemand_InfisicalXORValidation(t *testing.T) {
	// INFISICAL_CLIENT_ID set but INFISICAL_CLIENT_SECRET unset — must error.
	t.Setenv("INFISICAL_CLIENT_ID", "client-id")
	t.Setenv("INFISICAL_CLIENT_SECRET", "")

	ref := secrets.SecretRef{
		Name:     "my-secret",
		Provider: "infisical",
		Params:   map[string]string{},
	}

	_, err := resolveSecretOnDemand(context.Background(), ref)
	if err == nil {
		t.Fatal("expected error for mismatched Infisical credentials")
	}
	if !strings.Contains(err.Error(), "must both be set") {
		t.Errorf("error = %q, want contains 'must both be set'", err.Error())
	}
}
