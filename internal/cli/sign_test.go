package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/signing"
)

func TestSignSingleRef(t *testing.T) {
	ref := "registry.io/myimage@sha256:abc123"
	signer := signing.NewMockSigner()

	var outBuf bytes.Buffer
	cmd := newSignCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runSign(cmd, ref, "/tmp/cosign.key", "", "", "", nil, signer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "Signing registry.io/myimage@sha256:abc123") {
		t.Errorf("expected signing message, got:\n%s", output)
	}
	if !strings.Contains(output, "Signed: registry.io/myimage@sha256:abc123") {
		t.Errorf("expected signed confirmation, got:\n%s", output)
	}
}

func TestSignSingleRefKeyless(t *testing.T) {
	ref := "registry.io/myimage@sha256:abc123"
	signer := signing.NewMockSigner()

	var outBuf bytes.Buffer
	cmd := newSignCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runSign(cmd, ref, "", "user@example.com", "https://accounts.google.com", "", nil, signer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "Signed:") {
		t.Errorf("expected signed confirmation, got:\n%s", output)
	}
	if !strings.Contains(output, "Rekor log index:") {
		t.Errorf("expected Rekor log index for keyless, got:\n%s", output)
	}
	if !strings.Contains(output, "Fulcio certificate issued") {
		t.Errorf("expected Fulcio certificate message for keyless, got:\n%s", output)
	}
}

func TestSignSingleRefWithAnnotations(t *testing.T) {
	ref := "registry.io/myimage@sha256:abc123"

	var capturedOpts signing.SignOptions
	signer := signing.NewCosignSigner(signing.WithSignFunc(
		func(_ context.Context, gotRef string, opts signing.SignOptions) (*signing.SignResult, error) {
			capturedOpts = opts
			return &signing.SignResult{
				Ref:           gotRef,
				Digest:        "sha256:abc123",
				RekorLogIndex: -1,
				SignedAt:      time.Now().UTC(),
			}, nil
		},
	))

	var outBuf bytes.Buffer
	cmd := newSignCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	annotations := map[string]string{"env": "production", "team": "platform"}
	err := runSign(cmd, ref, "/tmp/key", "", "", "", annotations, signer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedOpts.Annotations["env"] != "production" {
		t.Errorf("expected annotation env=production, got: %v", capturedOpts.Annotations)
	}
	if capturedOpts.Annotations["team"] != "platform" {
		t.Errorf("expected annotation team=platform, got: %v", capturedOpts.Annotations)
	}
}

func TestSignSingleRefError(t *testing.T) {
	ref := "registry.io/myimage@sha256:abc123"

	signer := signing.NewCosignSigner(signing.WithSignFunc(
		func(_ context.Context, _ string, _ signing.SignOptions) (*signing.SignResult, error) {
			return nil, signing.ErrNotConfigured
		},
	))

	var outBuf bytes.Buffer
	cmd := newSignCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runSign(cmd, ref, "", "", "", "", nil, signer)
	if err == nil {
		t.Fatal("expected error from failing signer")
	}
	if !strings.Contains(err.Error(), "sign:") {
		t.Errorf("expected 'sign:' prefix in error, got: %v", err)
	}
}

func TestSignAllFromLockfile(t *testing.T) {
	dir := t.TempDir()

	configContent := `{
  "name": "test",
  "image": "registry.io/app:v1",
  "agent": {
    "tools": {
      "mcp": {
        "github": {
          "image": "registry.io/mcp-server:2.1"
        }
      },
      "skills": {
        "myskill": {
          "artifact": "registry.io/skills/review:v1"
        }
      }
    }
  }
}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "agentcontainer",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:img111",
				ResolvedAt: time.Now().UTC(),
			},
			MCP: map[string]config.ResolvedMCP{
				"github": {
					Digest:     "sha256:mcp222",
					ResolvedAt: time.Now().UTC(),
				},
			},
			Skills: map[string]config.ResolvedSkill{
				"myskill": {
					Digest:     "sha256:skill333",
					ResolvedAt: time.Now().UTC(),
				},
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	signer := signing.NewMockSigner()

	var outBuf bytes.Buffer
	cmd := newSignCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runSignAll(cmd, configPath, "", "/tmp/cosign.key", "", "", "", nil, signer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "Signed 3 artifact(s)") {
		t.Errorf("expected '3 artifact(s)' in output, got:\n%s", output)
	}
	if !strings.Contains(output, "image registry.io/app:v1") {
		t.Errorf("expected image label, got:\n%s", output)
	}
	if !strings.Contains(output, "mcp github") {
		t.Errorf("expected mcp label, got:\n%s", output)
	}
	if !strings.Contains(output, "skill myskill") {
		t.Errorf("expected skill label, got:\n%s", output)
	}
}

func TestSignAllEmptyLockfile(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "test", "image": "alpine:3"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "agentcontainer",
		Resolved:    config.ResolvedArtifacts{},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	var outBuf bytes.Buffer
	cmd := newSignCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runSignAll(cmd, configPath, "", "", "", "", "", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "No pinned OCI artifacts") {
		t.Errorf("expected 'No pinned OCI artifacts', got:\n%s", output)
	}
}

func TestSignAllPartialFailure(t *testing.T) {
	dir := t.TempDir()

	configContent := `{
  "name": "test",
  "image": "registry.io/app:v1",
  "agent": {
    "tools": {
      "mcp": {
        "github": {
          "image": "registry.io/mcp-server:2.1"
        }
      }
    }
  }
}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "agentcontainer",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:img111",
				ResolvedAt: time.Now().UTC(),
			},
			MCP: map[string]config.ResolvedMCP{
				"github": {
					Digest:     "sha256:mcp222",
					ResolvedAt: time.Now().UTC(),
				},
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	// Signer that fails for MCP but succeeds for image.
	callCount := 0
	signer := signing.NewCosignSigner(signing.WithSignFunc(
		func(_ context.Context, ref string, _ signing.SignOptions) (*signing.SignResult, error) {
			callCount++
			if strings.Contains(ref, "mcp-server") {
				return nil, signing.ErrNotConfigured
			}
			return &signing.SignResult{
				Ref:           ref,
				Digest:        "sha256:test",
				RekorLogIndex: -1,
				SignedAt:      time.Now().UTC(),
			}, nil
		},
	))

	var outBuf bytes.Buffer
	cmd := newSignCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runSignAll(cmd, configPath, "", "/tmp/key", "", "", "", nil, signer)
	if err == nil {
		t.Fatal("expected error for partial failure")
	}
	if !strings.Contains(err.Error(), "1 artifact(s) failed") {
		t.Errorf("expected '1 artifact(s) failed' in error, got: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "FAILED:") {
		t.Errorf("expected 'FAILED:' in output, got:\n%s", output)
	}
	if !strings.Contains(output, "Signed 1 artifact(s)") {
		t.Errorf("expected 'Signed 1 artifact(s)' in output, got:\n%s", output)
	}
}

func TestSignAllMissingConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "nonexistent.json")

	var outBuf bytes.Buffer
	cmd := newSignCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runSignAll(cmd, configPath, "", "", "", "", "", nil, nil)
	if err == nil {
		t.Fatal("expected error for missing config")
	}
}

func TestSignAllMissingLockfile(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "test", "image": "alpine:3"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	var outBuf bytes.Buffer
	cmd := newSignCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runSignAll(cmd, configPath, filepath.Join(dir, "missing-lock.json"), "", "", "", "", nil, nil)
	if err == nil {
		t.Fatal("expected error for missing lockfile")
	}
}

func TestSignCmdMutuallyExclusiveAllAndRef(t *testing.T) {
	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"sign", "--all", "registry.io/image@sha256:abc"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for --all with explicit ref")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected 'mutually exclusive' in error, got: %v", err)
	}
}

func TestSignCmdKeylessAndKeyMutuallyExclusive(t *testing.T) {
	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"sign", "--keyless", "--key", "cosign.key", "registry.io/image@sha256:abc"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for --keyless with --key")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected 'mutually exclusive' in error, got: %v", err)
	}
}

func TestSignCmdRequiresRefOrAll(t *testing.T) {
	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"sign"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when no ref or --all")
	}
	if !strings.Contains(err.Error(), "provide an OCI reference or use --all") {
		t.Errorf("expected usage hint in error, got: %v", err)
	}
}

func TestSignCmdFlags(t *testing.T) {
	cmd := newSignCmd()

	for _, flag := range []string{"key", "keyless", "cert-identity", "cert-issuer", "rekor-url", "config", "lockfile", "all", "annotation"} {
		f := cmd.Flags().Lookup(flag)
		if f == nil {
			t.Errorf("expected --%s flag", flag)
		}
	}
}

func TestSignCmdHelpText(t *testing.T) {
	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"sign", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("sign --help failed: %v", err)
	}

	output := outBuf.String()
	for _, expected := range []string{"--key", "--keyless", "--all", "--annotation", "Sigstore"} {
		if !strings.Contains(output, expected) {
			t.Errorf("expected %q in help text, got:\n%s", expected, output)
		}
	}
}

func TestParseAnnotations(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected map[string]string
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty input",
			input:    []string{},
			expected: nil,
		},
		{
			name:  "single annotation",
			input: []string{"env=production"},
			expected: map[string]string{
				"env": "production",
			},
		},
		{
			name:  "multiple annotations",
			input: []string{"env=production", "team=platform"},
			expected: map[string]string{
				"env":  "production",
				"team": "platform",
			},
		},
		{
			name:  "value with equals sign",
			input: []string{"msg=hello=world"},
			expected: map[string]string{
				"msg": "hello=world",
			},
		},
		{
			name:     "no equals sign (ignored)",
			input:    []string{"invalid"},
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAnnotations(tt.input)
			if tt.expected == nil {
				if got != nil {
					t.Errorf("expected nil, got: %v", got)
				}
				return
			}
			if len(got) != len(tt.expected) {
				t.Errorf("expected %d entries, got %d: %v", len(tt.expected), len(got), got)
				return
			}
			for k, v := range tt.expected {
				if got[k] != v {
					t.Errorf("expected %s=%s, got %s=%s", k, v, k, got[k])
				}
			}
		})
	}
}

func TestCollectSignableRefs(t *testing.T) {
	cfg := &config.AgentContainer{
		Image: "registry.io/app:v1",
		Features: map[string]any{
			"ghcr.io/features/node:1": map[string]any{},
		},
		Agent: &config.AgentConfig{
			Tools: &config.ToolsConfig{
				MCP: map[string]config.MCPToolConfig{
					"github": {Image: "registry.io/mcp:2"},
				},
				Skills: map[string]config.SkillConfig{
					"review": {Artifact: "registry.io/skills/review:v1"},
				},
			},
		},
	}

	lf := &config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "agentcontainer",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:img",
				ResolvedAt: time.Now().UTC(),
			},
			Features: map[string]config.ResolvedFeature{
				"ghcr.io/features/node:1": {
					Digest:     "sha256:feat",
					ResolvedAt: time.Now().UTC(),
				},
			},
			MCP: map[string]config.ResolvedMCP{
				"github": {
					Digest:     "sha256:mcp",
					ResolvedAt: time.Now().UTC(),
				},
			},
			Skills: map[string]config.ResolvedSkill{
				"review": {
					Digest:     "sha256:skill",
					ResolvedAt: time.Now().UTC(),
				},
			},
		},
	}

	refs := collectSignableRefs(cfg, lf)
	if len(refs) != 4 {
		t.Fatalf("expected 4 signable refs, got %d: %v", len(refs), refs)
	}

	// Check that refs contain digest-pinned references.
	found := make(map[string]bool)
	for _, r := range refs {
		found[r.ref] = true
	}

	expected := []string{
		"registry.io/app:v1@sha256:img",
		"ghcr.io/features/node:1@sha256:feat",
		"registry.io/mcp:2@sha256:mcp",
		"registry.io/skills/review:v1@sha256:skill",
	}
	for _, e := range expected {
		if !found[e] {
			t.Errorf("expected ref %q in signable refs, got: %v", e, refs)
		}
	}
}

func TestCollectSignableRefsNoTools(t *testing.T) {
	cfg := &config.AgentContainer{
		Image: "registry.io/app:v1",
	}

	lf := &config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "agentcontainer",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:img",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}

	refs := collectSignableRefs(cfg, lf)
	if len(refs) != 1 {
		t.Fatalf("expected 1 signable ref, got %d: %v", len(refs), refs)
	}
	if refs[0].ref != "registry.io/app:v1@sha256:img" {
		t.Errorf("unexpected ref: %s", refs[0].ref)
	}
}

func TestCollectSignableRefsUnlockedSkipped(t *testing.T) {
	cfg := &config.AgentContainer{
		Image: "registry.io/app:v1",
		Agent: &config.AgentConfig{
			Tools: &config.ToolsConfig{
				MCP: map[string]config.MCPToolConfig{
					"github": {Image: "registry.io/mcp:2"},
				},
			},
		},
	}

	// Lockfile only has image pinned, not MCP.
	lf := &config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "agentcontainer",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:img",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}

	refs := collectSignableRefs(cfg, lf)
	if len(refs) != 1 {
		t.Fatalf("expected 1 signable ref (unlocked MCP skipped), got %d: %v", len(refs), refs)
	}
}

func TestSignAllWithCustomLockfilePath(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "test", "image": "registry.io/app:v1"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	customLockPath := filepath.Join(dir, "custom-lock.json")
	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "agentcontainer",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:abc",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	data, _ := json.MarshalIndent(lf, "", "  ")
	data = append(data, '\n')
	if err := os.WriteFile(customLockPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	signer := signing.NewMockSigner()

	var outBuf bytes.Buffer
	cmd := newSignCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runSignAll(cmd, configPath, customLockPath, "/tmp/key", "", "", "", nil, signer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "Signed 1 artifact(s)") {
		t.Errorf("expected 'Signed 1 artifact(s)', got:\n%s", output)
	}
}

func TestSignAllWithRekorURL(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "test", "image": "registry.io/app:v1"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "agentcontainer",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:abc",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	var capturedOpts signing.SignOptions
	signer := signing.NewCosignSigner(signing.WithSignFunc(
		func(_ context.Context, ref string, opts signing.SignOptions) (*signing.SignResult, error) {
			capturedOpts = opts
			return &signing.SignResult{
				Ref:           ref,
				Digest:        "sha256:abc",
				RekorLogIndex: -1,
				SignedAt:      time.Now().UTC(),
			}, nil
		},
	))

	var outBuf bytes.Buffer
	cmd := newSignCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runSignAll(cmd, configPath, "", "/tmp/key", "", "", "https://rekor.example.com", nil, signer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedOpts.RekorURL != "https://rekor.example.com" {
		t.Errorf("expected rekor URL 'https://rekor.example.com', got %q", capturedOpts.RekorURL)
	}
}

func TestSignProvenanceSuccess(t *testing.T) {
	// Set up GitHub Actions environment.
	t.Setenv("GITHUB_ACTOR", "test-user")
	t.Setenv("GITHUB_WORKFLOW", "release.yml")
	t.Setenv("GITHUB_SHA", "abc123def456")
	t.Setenv("GITHUB_REF", "refs/tags/v1.0.0")
	t.Setenv("GITHUB_RUN_ID", "42")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("GITHUB_REPOSITORY", "Kubedoll-Heavy-Industries/agentcontainers")

	attester := signing.NewMockAttester()

	var outBuf bytes.Buffer
	cmd := newSignCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runSignProvenance(cmd, "ghcr.io/khi/ac@sha256:abc123def", "", "", attester)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "Generating SLSA provenance") {
		t.Errorf("expected provenance generation message, got:\n%s", output)
	}
	if !strings.Contains(output, "release.yml") {
		t.Errorf("expected workflow name in output, got:\n%s", output)
	}
	if !strings.Contains(output, "abc123def456") {
		t.Errorf("expected commit SHA in output, got:\n%s", output)
	}
	if !strings.Contains(output, "Provenance attestation attached") {
		t.Errorf("expected attestation confirmation, got:\n%s", output)
	}
	if !strings.Contains(output, "SLSA L3") {
		t.Errorf("expected SLSA level in output, got:\n%s", output)
	}
}

func TestSignProvenanceMissingEnv(t *testing.T) {
	// Clear all required env vars.
	t.Setenv("GITHUB_SHA", "")
	t.Setenv("GITHUB_WORKFLOW", "")
	t.Setenv("GITHUB_REPOSITORY", "")

	attester := signing.NewMockAttester()

	var outBuf bytes.Buffer
	cmd := newSignCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runSignProvenance(cmd, "ghcr.io/org/image@sha256:abc", "", "", attester)
	if err == nil {
		t.Fatal("expected error for missing GitHub env vars")
	}
	if !strings.Contains(err.Error(), "GITHUB_SHA") {
		t.Errorf("expected GITHUB_SHA in error, got: %v", err)
	}
}

func TestSignProvenanceBadRef(t *testing.T) {
	t.Setenv("GITHUB_SHA", "abc123")
	t.Setenv("GITHUB_WORKFLOW", "ci.yml")
	t.Setenv("GITHUB_REPOSITORY", "org/repo")

	attester := signing.NewMockAttester()

	var outBuf bytes.Buffer
	cmd := newSignCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runSignProvenance(cmd, "ghcr.io/org/image:latest", "", "", attester)
	if err == nil {
		t.Fatal("expected error for ref without digest")
	}
	if !strings.Contains(err.Error(), "must include a digest") {
		t.Errorf("expected digest error, got: %v", err)
	}
}

func TestSignProvenanceWithKey(t *testing.T) {
	t.Setenv("GITHUB_ACTOR", "test-user")
	t.Setenv("GITHUB_WORKFLOW", "ci.yml")
	t.Setenv("GITHUB_SHA", "abc123")
	t.Setenv("GITHUB_REF", "refs/heads/main")
	t.Setenv("GITHUB_RUN_ID", "")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("GITHUB_REPOSITORY", "org/repo")

	var capturedOpts signing.AttestOptions
	attester := signing.NewCosignAttester(signing.WithAttestFunc(
		func(_ context.Context, _ string, _ *signing.InTotoStatement, opts signing.AttestOptions) (*signing.AttestResult, error) {
			capturedOpts = opts
			return &signing.AttestResult{
				Ref:           "ghcr.io/org/image@sha256:abc",
				RekorLogIndex: -1,
			}, nil
		},
	))

	var outBuf bytes.Buffer
	cmd := newSignCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runSignProvenance(cmd, "ghcr.io/org/image@sha256:abc", "cosign.key", "https://rekor.example.com", attester)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedOpts.KeyPath != "cosign.key" {
		t.Errorf("expected KeyPath='cosign.key', got %q", capturedOpts.KeyPath)
	}
	if capturedOpts.RekorURL != "https://rekor.example.com" {
		t.Errorf("expected RekorURL='https://rekor.example.com', got %q", capturedOpts.RekorURL)
	}
}

func TestParseRefForAttestation(t *testing.T) {
	tests := []struct {
		name       string
		ref        string
		wantName   string
		wantDigest string
		wantErr    bool
	}{
		{
			name:       "valid ref",
			ref:        "ghcr.io/org/image@sha256:abc123",
			wantName:   "ghcr.io/org/image",
			wantDigest: "abc123",
		},
		{
			name:    "no digest",
			ref:     "ghcr.io/org/image:latest",
			wantErr: true,
		},
		{
			name:    "empty ref",
			ref:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, digest, err := parseRefForAttestation(tt.ref)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if digest["sha256"] != tt.wantDigest {
				t.Errorf("digest = %q, want %q", digest["sha256"], tt.wantDigest)
			}
		})
	}
}

func TestSignCmdProvenanceFlag(t *testing.T) {
	cmd := newSignCmd()
	f := cmd.Flags().Lookup("provenance")
	if f == nil {
		t.Error("expected --provenance flag")
	}
}
