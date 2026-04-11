package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/oci"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/signing"
)

func TestVerifyPasses(t *testing.T) {
	dir := t.TempDir()

	// Write a minimal config.
	configContent := `{"name": "test", "image": "alpine:3"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write a matching lockfile with the image pinned.
	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:abc123",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"verify", "--config", configPath, "--registry=false"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify command failed: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "Verification passed") {
		t.Errorf("expected 'Verification passed' in output, got:\n%s", output)
	}
}

func TestVerifyWarnsOnMissing(t *testing.T) {
	dir := t.TempDir()

	// Config references an image, features, and MCP server.
	configContent := `{
  "name": "test",
  "image": "alpine:3",
  "features": {
    "ghcr.io/devcontainers/features/node:1": {}
  },
  "agent": {
    "tools": {
      "mcp": {
        "github": {
          "image": "ghcr.io/github/mcp-server:2.1"
        }
      }
    }
  }
}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Lockfile is empty (nothing pinned).
	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved:    config.ResolvedArtifacts{},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"verify", "--config", configPath, "--registry=false"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify without --strict should not fail: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "MISSING: image:") {
		t.Errorf("expected image missing warning, got:\n%s", output)
	}
	if !strings.Contains(output, "MISSING: feature") {
		t.Errorf("expected feature missing warning, got:\n%s", output)
	}
	if !strings.Contains(output, "MISSING: mcp") {
		t.Errorf("expected mcp missing warning, got:\n%s", output)
	}
}

func TestVerifyStrictFails(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "test", "image": "alpine:3"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Empty lockfile: image not pinned.
	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved:    config.ResolvedArtifacts{},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"verify", "--config", configPath, "--strict", "--registry=false"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error in strict mode with unpinned image, got nil")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("expected 'missing' in error, got: %v", err)
	}
}

func TestVerifyMissingConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "nonexistent.json")

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"verify", "--config", configPath})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing config, got nil")
	}
}

func TestVerifyMissingLockfile(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "test", "image": "alpine:3"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"verify", "--config", configPath, "--lockfile", filepath.Join(dir, "missing-lock.json")})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing lockfile, got nil")
	}
}

func TestVerifyFlagDefaults(t *testing.T) {
	cmd := newVerifyCmd()

	configFlag := cmd.Flags().Lookup("config")
	if configFlag == nil {
		t.Fatal("expected --config flag")
	}
	if configFlag.DefValue != "" {
		t.Errorf("--config default = %q, want empty", configFlag.DefValue)
	}
	if configFlag.Shorthand != "c" {
		t.Errorf("--config shorthand = %q, want %q", configFlag.Shorthand, "c")
	}

	lockfileFlag := cmd.Flags().Lookup("lockfile")
	if lockfileFlag == nil {
		t.Fatal("expected --lockfile flag")
	}
	if lockfileFlag.DefValue != "" {
		t.Errorf("--lockfile default = %q, want empty", lockfileFlag.DefValue)
	}
	if lockfileFlag.Shorthand != "l" {
		t.Errorf("--lockfile shorthand = %q, want %q", lockfileFlag.Shorthand, "l")
	}

	strictFlag := cmd.Flags().Lookup("strict")
	if strictFlag == nil {
		t.Fatal("expected --strict flag")
	}
	if strictFlag.DefValue != "false" {
		t.Errorf("--strict default = %q, want %q", strictFlag.DefValue, "false")
	}

	registryFlag := cmd.Flags().Lookup("registry")
	if registryFlag == nil {
		t.Fatal("expected --registry flag")
	}
	if registryFlag.DefValue != "true" {
		t.Errorf("--registry default = %q, want %q", registryFlag.DefValue, "true")
	}
}

func TestVerifyHelpText(t *testing.T) {
	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"verify", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify --help failed: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "lockfile") {
		t.Errorf("expected 'lockfile' in help text, got:\n%s", output)
	}
	if !strings.Contains(output, "--config") {
		t.Errorf("expected '--config' in help text, got:\n%s", output)
	}
	if !strings.Contains(output, "--lockfile") {
		t.Errorf("expected '--lockfile' in help text, got:\n%s", output)
	}
	if !strings.Contains(output, "--strict") {
		t.Errorf("expected '--strict' in help text, got:\n%s", output)
	}
	if !strings.Contains(output, "--registry") {
		t.Errorf("expected '--registry' in help text, got:\n%s", output)
	}
}

func TestVerifyCustomLockfilePath(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "test", "image": "alpine:3"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write lockfile at a custom path.
	customLockPath := filepath.Join(dir, "custom-lock.json")
	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:abc123",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, customLockPath, &lf)

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"verify", "--config", configPath, "--lockfile", customLockPath, "--registry=false"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify with custom lockfile path failed: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "Verification passed") {
		t.Errorf("expected 'Verification passed' in output, got:\n%s", output)
	}
}

// --- Registry-based verification tests ---

// newMockRegistry creates a test registry server that returns known digests
// for specific image references. digestMap maps "name/tag" to a digest string.
func newMockRegistry(t *testing.T, digestMap map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Match manifest HEAD requests: /v2/<name>/manifests/<tag>
		path := r.URL.Path
		if r.Method == http.MethodHead && strings.Contains(path, "/manifests/") {
			// Extract the part after /v2/ and before /manifests/
			parts := strings.SplitN(strings.TrimPrefix(path, "/v2/"), "/manifests/", 2)
			if len(parts) == 2 {
				key := parts[0] + "/" + parts[1]
				if digest, ok := digestMap[key]; ok {
					w.Header().Set("Docker-Content-Digest", digest)
					w.WriteHeader(http.StatusOK)
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	return srv
}

func TestVerifyRegistryDigestMatch(t *testing.T) {
	dir := t.TempDir()
	lockedDigest := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// Set up mock registry that returns the same digest as the lockfile.
	srv := newMockRegistry(t, map[string]string{
		"library/alpine/3": lockedDigest,
	})
	defer srv.Close()

	// The image ref must point at our test server.
	imageRef := srv.Listener.Addr().String() + "/library/alpine:3"

	configContent := fmt.Sprintf(`{"name": "test", "image": "%s"}`, imageRef)
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     lockedDigest,
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	// Inject mock resolver pointing at our test server.
	oldFactory := resolverFactory
	resolverFactory = func() *oci.Resolver {
		return oci.NewResolver(oci.WithHTTPClient(srv.Client()))
	}
	defer func() { resolverFactory = oldFactory }()

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"verify", "--config", configPath, "--registry"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify should pass when digests match: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "pinned and up to date") {
		t.Errorf("expected 'pinned and up to date' in output, got:\n%s", output)
	}
}

func TestVerifyRegistryDigestMismatch(t *testing.T) {
	dir := t.TempDir()
	lockedDigest := "sha256:olddigest111111111111111111111111"
	registryDigest := "sha256:newdigest222222222222222222222222"

	srv := newMockRegistry(t, map[string]string{
		"library/alpine/3": registryDigest,
	})
	defer srv.Close()

	imageRef := srv.Listener.Addr().String() + "/library/alpine:3"

	configContent := fmt.Sprintf(`{"name": "test", "image": "%s"}`, imageRef)
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     lockedDigest,
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	oldFactory := resolverFactory
	resolverFactory = func() *oci.Resolver {
		return oci.NewResolver(oci.WithHTTPClient(srv.Client()))
	}
	defer func() { resolverFactory = oldFactory }()

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"verify", "--config", configPath, "--registry"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify without --strict should not error: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "STALE:") {
		t.Errorf("expected 'STALE:' in output, got:\n%s", output)
	}
	if !strings.Contains(output, lockedDigest) {
		t.Errorf("expected old digest %s in output, got:\n%s", lockedDigest, output)
	}
	if !strings.Contains(output, registryDigest) {
		t.Errorf("expected new digest %s in output, got:\n%s", registryDigest, output)
	}
}

func TestVerifyRegistryDigestMismatchStrict(t *testing.T) {
	dir := t.TempDir()
	lockedDigest := "sha256:olddigest111111111111111111111111"
	registryDigest := "sha256:newdigest222222222222222222222222"

	srv := newMockRegistry(t, map[string]string{
		"library/alpine/3": registryDigest,
	})
	defer srv.Close()

	imageRef := srv.Listener.Addr().String() + "/library/alpine:3"

	configContent := fmt.Sprintf(`{"name": "test", "image": "%s"}`, imageRef)
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     lockedDigest,
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	oldFactory := resolverFactory
	resolverFactory = func() *oci.Resolver {
		return oci.NewResolver(oci.WithHTTPClient(srv.Client()))
	}
	defer func() { resolverFactory = oldFactory }()

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"verify", "--config", configPath, "--registry", "--strict"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error in strict mode with stale digest")
	}
	if !strings.Contains(err.Error(), "stale") {
		t.Errorf("expected 'stale' in error, got: %v", err)
	}
}

func TestVerifyRegistryMCPAndSkills(t *testing.T) {
	dir := t.TempDir()
	mcpDigest := "sha256:mcp-locked-digest-11111111"
	mcpLiveDigest := "sha256:mcp-live-digest-22222222"
	skillDigest := "sha256:skill-locked-digest-33333333"

	srv := newMockRegistry(t, map[string]string{
		"github/mcp-server/2.1": mcpLiveDigest, // different from lockfile
		"org/myskill/v1":        skillDigest,   // same as lockfile
	})
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	configContent := fmt.Sprintf(`{
  "name": "test",
  "image": "%s/library/alpine:3",
  "agent": {
    "tools": {
      "mcp": {
        "github": {
          "image": "%s/github/mcp-server:2.1"
        }
      },
      "skills": {
        "myskill": {
          "artifact": "%s/org/myskill:v1"
        }
      }
    }
  }
}`, addr, addr, addr)
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	imageDigest := "sha256:image-digest-44444444"
	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     imageDigest,
				ResolvedAt: time.Now().UTC(),
			},
			MCP: map[string]config.ResolvedMCP{
				"github": {
					Digest:     mcpDigest,
					ResolvedAt: time.Now().UTC(),
				},
			},
			Skills: map[string]config.ResolvedSkill{
				"myskill": {
					Digest:     skillDigest,
					ResolvedAt: time.Now().UTC(),
				},
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	// Mock registry returns different MCP digest, same skill digest, and
	// image returns 404 (will be reported as error).
	oldFactory := resolverFactory
	resolverFactory = func() *oci.Resolver {
		return oci.NewResolver(oci.WithHTTPClient(srv.Client()))
	}
	defer func() { resolverFactory = oldFactory }()

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"verify", "--config", configPath, "--registry"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify without --strict should not error: %v", err)
	}

	output := outBuf.String()
	// MCP should be stale (digest changed).
	if !strings.Contains(output, "STALE: mcp github") {
		t.Errorf("expected stale MCP warning, got:\n%s", output)
	}
	// Skill should NOT be stale (digest matches).
	if strings.Contains(output, "STALE: skill") {
		t.Errorf("skill should not be stale, got:\n%s", output)
	}
	// Image should have an error (404 from mock registry).
	if !strings.Contains(output, "ERROR: image") {
		t.Errorf("expected error for image (registry 404), got:\n%s", output)
	}
}

func TestVerifyNoRegistryFlag(t *testing.T) {
	dir := t.TempDir()
	lockedDigest := "sha256:old-digest-that-would-be-stale"

	configContent := `{"name": "test", "image": "alpine:3"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     lockedDigest,
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"verify", "--config", configPath, "--registry=false"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify --no-registry should pass with coverage only: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "Verification passed") {
		t.Errorf("expected 'Verification passed' in output, got:\n%s", output)
	}
	if strings.Contains(output, "STALE") {
		t.Errorf("should not check registry with --no-registry, got:\n%s", output)
	}
}

func TestVerifyRegistryWithBearerAuth(t *testing.T) {
	dir := t.TempDir()
	lockedDigest := "sha256:abc123locked"
	registryDigest := "sha256:xyz789live"
	wantToken := "test-verify-token"

	var srvURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Token endpoint.
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"token": wantToken})
			return
		}
		// Registry manifest endpoint — requires auth.
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+wantToken {
			w.Header().Set("Www-Authenticate",
				fmt.Sprintf(`Bearer realm="%s/token",service="test"`, srvURL))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodHead && strings.HasSuffix(r.URL.Path, "/manifests/3") {
			w.Header().Set("Docker-Content-Digest", registryDigest)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	srvURL = srv.URL

	imageRef := srv.Listener.Addr().String() + "/library/alpine:3"
	configContent := fmt.Sprintf(`{"name": "test", "image": "%s"}`, imageRef)
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     lockedDigest,
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	oldFactory := resolverFactory
	resolverFactory = func() *oci.Resolver {
		return oci.NewResolver(oci.WithHTTPClient(srv.Client()))
	}
	defer func() { resolverFactory = oldFactory }()

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"verify", "--config", configPath, "--registry"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify should not error without --strict: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "STALE:") {
		t.Errorf("expected stale digest report, got:\n%s", output)
	}
}

func TestVerifyRegistryDigests(t *testing.T) {
	// Unit test for verifyRegistryDigests directly.
	cfg := &config.AgentContainer{
		Image: "myregistry.io/myimage:v1",
		Features: map[string]any{
			"myregistry.io/features/node:1": map[string]any{},
		},
		Agent: &config.AgentConfig{
			Tools: &config.ToolsConfig{
				MCP: map[string]config.MCPToolConfig{
					"mygithub": {Image: "myregistry.io/mcp/github:2"},
				},
				Skills: map[string]config.SkillConfig{
					"myskill": {Artifact: "myregistry.io/skills/myskill:v1"},
				},
			},
		},
	}

	lf := &config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:image-old",
				ResolvedAt: time.Now().UTC(),
			},
			Features: map[string]config.ResolvedFeature{
				"myregistry.io/features/node:1": {
					Digest:     "sha256:feature-current",
					ResolvedAt: time.Now().UTC(),
				},
			},
			MCP: map[string]config.ResolvedMCP{
				"mygithub": {
					Digest:     "sha256:mcp-old",
					ResolvedAt: time.Now().UTC(),
				},
			},
			Skills: map[string]config.ResolvedSkill{
				"myskill": {
					Digest:     "sha256:skill-current",
					ResolvedAt: time.Now().UTC(),
				},
			},
		},
	}

	// Mock resolver that returns known digests.
	mock := &mockResolver{
		digests: map[string]string{
			"myregistry.io/myimage:v1":        "sha256:image-new",       // changed
			"myregistry.io/features/node:1":   "sha256:feature-current", // same
			"myregistry.io/mcp/github:2":      "sha256:mcp-new",         // changed
			"myregistry.io/skills/myskill:v1": "sha256:skill-current",   // same
		},
	}

	var result verifyResult
	verifyRegistryDigests(context.Background(), cfg, lf, mock, &result)

	if len(result.stale) != 2 {
		t.Errorf("expected 2 stale entries, got %d: %v", len(result.stale), result.stale)
	}
	if len(result.errors) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(result.errors), result.errors)
	}

	// Check that the stale entries mention image and mcp.
	staleJoined := strings.Join(result.stale, "\n")
	if !strings.Contains(staleJoined, "image") {
		t.Errorf("expected stale image entry, got: %s", staleJoined)
	}
	if !strings.Contains(staleJoined, "mcp") {
		t.Errorf("expected stale mcp entry, got: %s", staleJoined)
	}
}

func TestVerifyRegistryDigestsResolverError(t *testing.T) {
	cfg := &config.AgentContainer{
		Image: "failing-registry.io/myimage:v1",
	}

	lf := &config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:abc",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}

	mock := &mockResolver{
		err: fmt.Errorf("connection refused"),
	}

	var result verifyResult
	verifyRegistryDigests(context.Background(), cfg, lf, mock, &result)

	if len(result.errors) != 1 {
		t.Errorf("expected 1 error, got %d: %v", len(result.errors), result.errors)
	}
	if len(result.stale) != 0 {
		t.Errorf("expected 0 stale, got %d: %v", len(result.stale), result.stale)
	}
}

// mockResolver implements the Resolve interface for unit testing.
type mockResolver struct {
	digests map[string]string
	err     error
}

func (m *mockResolver) Resolve(_ context.Context, ref string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	digest, ok := m.digests[ref]
	if !ok {
		return "", fmt.Errorf("unknown reference: %s", ref)
	}
	return digest, nil
}

// --- Signature verification tests ---

func TestVerifySignaturesFlags(t *testing.T) {
	cmd := newVerifyCmd()

	for _, flag := range []string{"signatures", "key", "cert-identity", "cert-issuer"} {
		f := cmd.Flags().Lookup(flag)
		if f == nil {
			t.Errorf("expected --%s flag", flag)
		}
	}
}

func TestVerifyWithSignaturesPass(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "test", "image": "alpine:3"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:abc123",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	verifier := signing.NewMockVerifier()

	var outBuf bytes.Buffer
	cmd := newVerifyCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runVerifyFull(cmd, configPath, "", false, false,
		&sigVerifyOpts{KeyPath: "/tmp/key.pub"}, false, verifier, nil, "", nil)
	if err != nil {
		t.Fatalf("verify with signatures should pass: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "signature(s) verified") {
		t.Errorf("expected 'signature(s) verified' in output, got:\n%s", output)
	}
}

func TestVerifyWithSignaturesFail(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "test", "image": "alpine:3"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:abc123",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	verifier := signing.NewMockVerifierFailing()

	var outBuf bytes.Buffer
	cmd := newVerifyCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	// Non-strict: should not return error but should report SIG FAIL.
	err := runVerifyFull(cmd, configPath, "", false, false,
		&sigVerifyOpts{}, false, verifier, nil, "", nil)
	if err != nil {
		t.Fatalf("verify without strict should not error: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "SIG FAIL:") {
		t.Errorf("expected 'SIG FAIL:' in output, got:\n%s", output)
	}
}

func TestVerifyWithSignaturesStrictFail(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "test", "image": "alpine:3"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:abc123",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	verifier := signing.NewMockVerifierFailing()

	var outBuf bytes.Buffer
	cmd := newVerifyCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runVerifyFull(cmd, configPath, "", true, false,
		&sigVerifyOpts{}, false, verifier, nil, "", nil)
	if err == nil {
		t.Fatal("expected error in strict mode with failed signatures")
	}
	if !strings.Contains(err.Error(), "sig-fail") {
		t.Errorf("expected 'sig-fail' in error, got: %v", err)
	}
}

func TestVerifySignaturesMultipleArtifacts(t *testing.T) {
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
          "artifact": "registry.io/skills/myskill:v1"
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
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:img123",
				ResolvedAt: time.Now().UTC(),
			},
			MCP: map[string]config.ResolvedMCP{
				"github": {
					Digest:     "sha256:mcp456",
					ResolvedAt: time.Now().UTC(),
				},
			},
			Skills: map[string]config.ResolvedSkill{
				"myskill": {
					Digest:     "sha256:skill789",
					ResolvedAt: time.Now().UTC(),
				},
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	verifier := signing.NewMockVerifier()

	var outBuf bytes.Buffer
	cmd := newVerifyCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runVerifyFull(cmd, configPath, "", false, false,
		&sigVerifyOpts{
			CertIdentity: "ci@example.com",
			CertIssuer:   "https://accounts.google.com",
		}, false, verifier, nil, "", nil)
	if err != nil {
		t.Fatalf("verify should pass: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "3 signature(s) verified") {
		t.Errorf("expected '3 signature(s) verified' in output, got:\n%s", output)
	}
}

func TestVerifyWithoutSignaturesFlag(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "test", "image": "alpine:3"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:abc123",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	var outBuf bytes.Buffer
	cmd := newVerifyCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	// sigOpts is nil = no signature verification.
	err := runVerifyFull(cmd, configPath, "", false, false, nil, false, nil, nil, "", nil)
	if err != nil {
		t.Fatalf("verify without signatures should pass: %v", err)
	}

	output := outBuf.String()
	if strings.Contains(output, "SIG") {
		t.Errorf("should not contain signature results without --signatures, got:\n%s", output)
	}
}

func TestVerifySignaturesUnit(t *testing.T) {
	cfg := &config.AgentContainer{
		Image: "registry.io/myimage:v1",
		Agent: &config.AgentConfig{
			Tools: &config.ToolsConfig{
				MCP: map[string]config.MCPToolConfig{
					"gh": {Image: "registry.io/mcp:2"},
				},
			},
		},
	}

	lf := &config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:img",
				ResolvedAt: time.Now().UTC(),
			},
			MCP: map[string]config.ResolvedMCP{
				"gh": {
					Digest:     "sha256:mcp",
					ResolvedAt: time.Now().UTC(),
				},
			},
		},
	}

	verifier := signing.NewMockVerifier()
	opts := &sigVerifyOpts{KeyPath: "/tmp/key.pub"}

	var result verifyResult
	verifySignatures(context.Background(), cfg, lf, verifier, opts, &result)

	if len(result.sigValid) != 2 {
		t.Errorf("expected 2 valid signatures, got %d: %v", len(result.sigValid), result.sigValid)
	}
	if len(result.sigInvalid) != 0 {
		t.Errorf("expected 0 invalid signatures, got %d: %v", len(result.sigInvalid), result.sigInvalid)
	}
}

// --- Offline verification CLI tests ---

func TestVerifyOfflineFlags(t *testing.T) {
	cmd := newVerifyCmd()

	for _, flag := range []string{"offline", "trusted-root", "bundle", "certificate-chain"} {
		f := cmd.Flags().Lookup(flag)
		if f == nil {
			t.Errorf("expected --%s flag", flag)
		}
	}

	// Check defaults.
	offlineFlag := cmd.Flags().Lookup("offline")
	if offlineFlag.DefValue != "false" {
		t.Errorf("--offline default = %q, want %q", offlineFlag.DefValue, "false")
	}
}

func TestVerifyOfflineWithKeyPass(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "test", "image": "alpine:3"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:abc123",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	verifier := signing.NewMockVerifierOffline()

	var outBuf bytes.Buffer
	cmd := newVerifyCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runVerifyFull(cmd, configPath, "", false, false,
		&sigVerifyOpts{
			KeyPath: "/tmp/cosign.pub",
			Offline: true,
		}, false, verifier, nil, "", nil)
	if err != nil {
		t.Fatalf("verify offline with key should pass: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "signature(s) verified") {
		t.Errorf("expected 'signature(s) verified' in output, got:\n%s", output)
	}
	if !strings.Contains(output, "(offline)") {
		t.Errorf("expected '(offline)' annotation in output, got:\n%s", output)
	}
}

func TestVerifyOfflineWithBundlePass(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "test", "image": "alpine:3"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:abc123",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	verifier := signing.NewMockVerifier()

	var outBuf bytes.Buffer
	cmd := newVerifyCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runVerifyFull(cmd, configPath, "", false, false,
		&sigVerifyOpts{
			KeyPath:    "/tmp/cosign.pub",
			BundlePath: "/tmp/artifact.sigstore.json",
			Offline:    true,
		}, false, verifier, nil, "", nil)
	if err != nil {
		t.Fatalf("verify offline with bundle should pass: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "signature(s) verified") {
		t.Errorf("expected 'signature(s) verified' in output, got:\n%s", output)
	}
	if !strings.Contains(output, "(offline)") {
		t.Errorf("expected '(offline)' in output, got:\n%s", output)
	}
}

func TestVerifyOfflineDisablesRegistry(t *testing.T) {
	// When --offline is set via the command, registry should be disabled.
	// We test this via the CLI flag path.
	dir := t.TempDir()

	configContent := `{"name": "test", "image": "alpine:3"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:abc123",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	verifier := signing.NewMockVerifierOffline()

	var outBuf bytes.Buffer
	cmd := newVerifyCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	// Offline with registry=false: should pass without contacting any registry.
	err := runVerifyFull(cmd, configPath, "", false, false,
		&sigVerifyOpts{
			KeyPath: "/tmp/cosign.pub",
			Offline: true,
		}, false, verifier, nil, "", nil)
	if err != nil {
		t.Fatalf("verify offline should pass: %v", err)
	}

	output := outBuf.String()
	// Should NOT contain "up to date" (that is from registry check).
	if strings.Contains(output, "up to date") {
		t.Errorf("offline mode should not show 'up to date' (implies registry check), got:\n%s", output)
	}
}

func TestVerifyOfflineSignaturesShowAnnotations(t *testing.T) {
	// When all signatures pass but there's a missing artifact, the detailed
	// per-artifact lines (SIG OK with annotations) are printed. We create
	// that scenario by having one unpinned feature so total > 0.
	dir := t.TempDir()

	configContent := `{
  "name": "test",
  "image": "registry.io/app:v1",
  "features": {
    "ghcr.io/devcontainers/features/node:1": {}
  },
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

	// Lockfile has image and MCP pinned, but NOT the feature — so we get
	// MISSING for the feature, which causes total > 0 and the detailed
	// SIG OK lines to be printed.
	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:img123",
				ResolvedAt: time.Now().UTC(),
			},
			MCP: map[string]config.ResolvedMCP{
				"github": {
					Digest:     "sha256:mcp456",
					ResolvedAt: time.Now().UTC(),
				},
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	verifier := signing.NewMockVerifier()

	var outBuf bytes.Buffer
	cmd := newVerifyCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runVerifyFull(cmd, configPath, "", false, false,
		&sigVerifyOpts{
			KeyPath:    "/tmp/cosign.pub",
			BundlePath: "/tmp/artifact.sigstore.json",
			Offline:    true,
		}, false, verifier, nil, "", nil)
	if err != nil {
		t.Fatalf("verify should not error without strict: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "[offline]") {
		t.Errorf("expected '[offline]' annotation in SIG OK lines, got:\n%s", output)
	}
	if !strings.Contains(output, "[bundle]") {
		t.Errorf("expected '[bundle]' annotation in SIG OK lines, got:\n%s", output)
	}
	if !strings.Contains(output, "MISSING: feature") {
		t.Errorf("expected MISSING feature entry, got:\n%s", output)
	}
}

func TestVerifyOfflineFailsWithStrict(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "test", "image": "alpine:3"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:abc123",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	verifier := signing.NewMockVerifierFailing()

	var outBuf bytes.Buffer
	cmd := newVerifyCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runVerifyFull(cmd, configPath, "", true, false,
		&sigVerifyOpts{
			KeyPath: "/tmp/cosign.pub",
			Offline: true,
		}, false, verifier, nil, "", nil)
	if err == nil {
		t.Fatal("expected error in strict mode with failed offline signatures")
	}
	if !strings.Contains(err.Error(), "sig-fail") {
		t.Errorf("expected 'sig-fail' in error, got: %v", err)
	}
}

func TestVerifyOfflinePassesOptsToSigning(t *testing.T) {
	// Test that the offline options from sigVerifyOpts are correctly propagated
	// to signing.VerifyOptions in verifySignatures.
	cfg := &config.AgentContainer{
		Image: "registry.io/myimage:v1",
	}

	lf := &config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:img",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}

	var capturedOpts signing.VerifyOptions
	verifier := signing.NewCosignVerifier(signing.WithVerifyFunc(
		func(_ context.Context, _ string, opts signing.VerifyOptions) (*signing.VerifyResult, error) {
			capturedOpts = opts
			return &signing.VerifyResult{
				Verified: true,
				Offline:  opts.Offline,
			}, nil
		},
	))

	opts := &sigVerifyOpts{
		KeyPath:              "/tmp/cosign.pub",
		Offline:              true,
		TrustedRootPath:      "/tmp/root.json",
		BundlePath:           "/tmp/artifact.sigstore.json",
		CertificateChainPath: "/tmp/chain.pem",
	}

	var result verifyResult
	verifySignatures(context.Background(), cfg, lf, verifier, opts, &result)

	if !capturedOpts.Offline {
		t.Error("expected Offline=true in signing options")
	}
	if capturedOpts.TrustedRootPath != "/tmp/root.json" {
		t.Errorf("expected TrustedRootPath=%q, got %q", "/tmp/root.json", capturedOpts.TrustedRootPath)
	}
	if capturedOpts.BundlePath != "/tmp/artifact.sigstore.json" {
		t.Errorf("expected BundlePath=%q, got %q", "/tmp/artifact.sigstore.json", capturedOpts.BundlePath)
	}
	if capturedOpts.CertificateChainPath != "/tmp/chain.pem" {
		t.Errorf("expected CertificateChainPath=%q, got %q", "/tmp/chain.pem", capturedOpts.CertificateChainPath)
	}
}

func TestVerifySignaturesUnitOffline(t *testing.T) {
	// Unit test for verifySignatures with offline options, verifying annotations.
	cfg := &config.AgentContainer{
		Image: "registry.io/myimage:v1",
		Agent: &config.AgentConfig{
			Tools: &config.ToolsConfig{
				MCP: map[string]config.MCPToolConfig{
					"gh": {Image: "registry.io/mcp:2"},
				},
			},
		},
	}

	lf := &config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:img",
				ResolvedAt: time.Now().UTC(),
			},
			MCP: map[string]config.ResolvedMCP{
				"gh": {
					Digest:     "sha256:mcp",
					ResolvedAt: time.Now().UTC(),
				},
			},
		},
	}

	verifier := signing.NewMockVerifier()
	opts := &sigVerifyOpts{
		KeyPath:    "/tmp/key.pub",
		BundlePath: "/tmp/bundle.sigstore.json",
		Offline:    true,
	}

	var result verifyResult
	verifySignatures(context.Background(), cfg, lf, verifier, opts, &result)

	if len(result.sigValid) != 2 {
		t.Errorf("expected 2 valid signatures, got %d: %v", len(result.sigValid), result.sigValid)
	}

	// Check offline and bundle annotations appear.
	validJoined := strings.Join(result.sigValid, "\n")
	if !strings.Contains(validJoined, "[offline]") {
		t.Errorf("expected '[offline]' in signature results, got: %s", validJoined)
	}
	if !strings.Contains(validJoined, "[bundle]") {
		t.Errorf("expected '[bundle]' in signature results, got: %s", validJoined)
	}
}

func TestVerifyProvenancePass(t *testing.T) {
	dir := t.TempDir()

	// Config with provenance requirements.
	configContent := `{
		"name": "test",
		"image": "ghcr.io/org/image:v1",
		"agent": {
			"provenance": {
				"require": {
					"slsaLevel": 2,
					"trustedBuilders": ["https://github.com/slsa-framework/slsa-github-generator"]
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
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:abc123",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	prov := &signing.Provenance{
		Builder: signing.ProvenanceBuilder{
			ID: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0",
		},
		Invocation: signing.ProvenanceInvocation{
			ConfigSource: signing.ProvenanceConfigSource{
				URI:    "git+https://github.com/org/repo@refs/heads/main",
				Digest: map[string]string{"sha1": "abc123def"},
			},
		},
	}
	provVerifier := signing.NewMockProvenanceVerifier(prov)

	var outBuf bytes.Buffer
	cmd := newVerifyCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runVerifyFull(cmd, configPath, "", false, false,
		nil, true, nil, provVerifier, "", nil)
	if err != nil {
		t.Fatalf("verify with provenance should pass: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "provenance attestation(s) verified") {
		t.Errorf("expected provenance verification message in output, got:\n%s", output)
	}
}

func TestVerifyProvenanceFailsUntrustedBuilder(t *testing.T) {
	dir := t.TempDir()

	configContent := `{
		"name": "test",
		"image": "ghcr.io/org/image:v1",
		"agent": {
			"provenance": {
				"require": {
					"slsaLevel": 1,
					"trustedBuilders": ["https://github.com/slsa-framework/slsa-github-generator"]
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
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:abc123",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	// Use an untrusted builder.
	prov := &signing.Provenance{
		Builder: signing.ProvenanceBuilder{
			ID: "https://untrusted-ci.example.com/builder",
		},
	}
	provVerifier := signing.NewMockProvenanceVerifier(prov)

	var outBuf bytes.Buffer
	cmd := newVerifyCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	// Non-strict: should report but not error.
	err := runVerifyFull(cmd, configPath, "", false, false,
		nil, true, nil, provVerifier, "", nil)
	if err != nil {
		t.Fatalf("verify without strict should not error: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "PROV FAIL") {
		t.Errorf("expected 'PROV FAIL' in output, got:\n%s", output)
	}
	if !strings.Contains(output, "not in trusted builders list") {
		t.Errorf("expected 'not in trusted builders list' in output, got:\n%s", output)
	}
}

func TestVerifyProvenanceStrictFails(t *testing.T) {
	dir := t.TempDir()

	configContent := `{
		"name": "test",
		"image": "ghcr.io/org/image:v1",
		"agent": {
			"provenance": {
				"require": {
					"slsaLevel": 3
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
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:abc123",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	// Builder with only SLSA L1.
	prov := &signing.Provenance{
		Builder: signing.ProvenanceBuilder{ID: "local-builder"},
	}
	provVerifier := signing.NewMockProvenanceVerifier(prov)

	var outBuf bytes.Buffer
	cmd := newVerifyCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runVerifyFull(cmd, configPath, "", true, false,
		nil, true, nil, provVerifier, "", nil)
	if err == nil {
		t.Fatal("expected error in strict mode with failed provenance")
	}
	if !strings.Contains(err.Error(), "prov-fail") {
		t.Errorf("expected 'prov-fail' in error, got: %v", err)
	}
}

func TestVerifyProvenanceNoRequirements(t *testing.T) {
	// When no provenance requirements are configured, provenance check
	// should still pass (trustedBuilders empty => skip builder validation).
	dir := t.TempDir()

	configContent := `{"name": "test", "image": "alpine:3"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:abc123",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	prov := &signing.Provenance{
		Builder: signing.ProvenanceBuilder{ID: "any-builder"},
	}
	provVerifier := signing.NewMockProvenanceVerifier(prov)

	var outBuf bytes.Buffer
	cmd := newVerifyCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runVerifyFull(cmd, configPath, "", false, false,
		nil, true, nil, provVerifier, "", nil)
	if err != nil {
		t.Fatalf("verify without provenance requirements should pass: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "provenance attestation(s) verified") {
		t.Errorf("expected provenance verification message, got:\n%s", output)
	}
}

func TestVerifyProvenanceUnit(t *testing.T) {
	// Unit test for verifyProvenance checking all artifact types.
	cfg := &config.AgentContainer{
		Image: "registry.io/myimage:v1",
		Agent: &config.AgentConfig{
			Provenance: &config.ProvenanceConfig{
				Require: &config.ProvenanceRequirements{
					SLSALevel:       2,
					TrustedBuilders: []string{"https://github.com/slsa-framework"},
				},
			},
			Tools: &config.ToolsConfig{
				MCP: map[string]config.MCPToolConfig{
					"gh": {Image: "registry.io/mcp:2"},
				},
			},
		},
	}

	lf := &config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:img",
				ResolvedAt: time.Now().UTC(),
			},
			MCP: map[string]config.ResolvedMCP{
				"gh": {
					Digest:     "sha256:mcp",
					ResolvedAt: time.Now().UTC(),
				},
			},
		},
	}

	prov := &signing.Provenance{
		Builder: signing.ProvenanceBuilder{
			ID: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/ci.yml",
		},
		Invocation: signing.ProvenanceInvocation{
			ConfigSource: signing.ProvenanceConfigSource{
				URI:    "git+https://github.com/org/repo@refs/heads/main",
				Digest: map[string]string{"sha1": "abc123"},
			},
		},
	}
	provVerifier := signing.NewMockProvenanceVerifier(prov)

	var result verifyResult
	verifyProvenance(context.Background(), cfg, lf, provVerifier, &result)

	if len(result.provValid) != 2 {
		t.Errorf("expected 2 valid provenance results, got %d: %v", len(result.provValid), result.provValid)
	}
	if len(result.provInvalid) != 0 {
		t.Errorf("expected 0 invalid provenance, got %d: %v", len(result.provInvalid), result.provInvalid)
	}
}

// mockBundleFetcher implements bundleFetcher for testing.
type mockBundleFetcher struct {
	bundles map[string][]byte // imageRef → bundle JSON
	err     error
}

func (m *mockBundleFetcher) FetchSigstoreBundle(_ context.Context, imageRef string) ([]byte, string, error) {
	if m.err != nil {
		return nil, "", m.err
	}
	data, ok := m.bundles[imageRef]
	if !ok {
		return nil, "", fmt.Errorf("no bundle for %s", imageRef)
	}
	return data, "sha256:bundledigest", nil
}

func TestSaveBundleFlag_RequiresSignatures(t *testing.T) {
	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetErr(&outBuf)
	cmd.SetArgs([]string{"verify", "--save-bundle", "/tmp/bundles", "--config", "nonexistent.json"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when --save-bundle without --signatures")
	}
	if !strings.Contains(err.Error(), "--save-bundle requires --signatures") {
		t.Errorf("expected '--save-bundle requires --signatures' error, got: %v", err)
	}
}

func TestSaveBundleFlag_IncompatibleWithOffline(t *testing.T) {
	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetErr(&outBuf)
	cmd.SetArgs([]string{
		"verify", "--save-bundle", "/tmp/bundles",
		"--signatures", "--offline",
		"--key", "/tmp/key.pub",
		"--config", "nonexistent.json",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when --save-bundle with --offline")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected 'mutually exclusive' error, got: %v", err)
	}
}

func TestSaveBundles_Success(t *testing.T) {
	dir := t.TempDir()

	// Write a config with an image.
	configContent := `{"name": "test", "image": "ghcr.io/myorg/myimage:v1"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write a lockfile.
	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:abc123",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	bundleJSON := `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`
	fetcher := &mockBundleFetcher{
		bundles: map[string][]byte{
			"ghcr.io/myorg/myimage:v1@sha256:abc123": []byte(bundleJSON),
		},
	}

	verifier := signing.NewMockVerifier()
	bundleDir := filepath.Join(t.TempDir(), "bundles")

	var outBuf bytes.Buffer
	cmd := newVerifyCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runVerifyFull(cmd, configPath, "", false, false,
		&sigVerifyOpts{KeyPath: "/tmp/key.pub"}, false, verifier, nil, bundleDir, fetcher)
	if err != nil {
		t.Fatalf("verify with save-bundle should pass: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "Saved 1 bundle(s)") {
		t.Errorf("expected 'Saved 1 bundle(s)' in output, got:\n%s", output)
	}

	// Verify the bundle file was created.
	expectedPath := filepath.Join(bundleDir, "ghcr.io", "myorg/myimage", "sha256-abc123.sigstore.json")
	data, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("reading saved bundle: %v", err)
	}
	if string(data) != bundleJSON {
		t.Errorf("saved bundle = %q, want %q", string(data), bundleJSON)
	}
}

func TestSaveBundles_FetchError(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "test", "image": "ghcr.io/myorg/myimage:v1"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:abc123",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	fetcher := &mockBundleFetcher{
		bundles: map[string][]byte{}, // no bundles available
	}

	verifier := signing.NewMockVerifier()
	bundleDir := filepath.Join(t.TempDir(), "bundles")

	var outBuf bytes.Buffer
	cmd := newVerifyCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runVerifyFull(cmd, configPath, "", false, false,
		&sigVerifyOpts{KeyPath: "/tmp/key.pub"}, false, verifier, nil, bundleDir, fetcher)
	if err != nil {
		t.Fatalf("verify should pass even if bundle save fails: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "WARNING: saving bundles") {
		t.Errorf("expected warning about failed bundle save, got:\n%s", output)
	}
}

func TestSaveBundles_NoSaveWhenNoSigValid(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "test", "image": "ghcr.io/myorg/myimage:v1"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "ac",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:abc123",
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &lf)

	// Use a failing verifier — no valid sigs, so save-bundle should be skipped.
	verifier := signing.NewMockVerifierFailing()
	bundleDir := filepath.Join(t.TempDir(), "bundles")

	var outBuf bytes.Buffer
	cmd := newVerifyCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	_ = runVerifyFull(cmd, configPath, "", false, false,
		&sigVerifyOpts{KeyPath: "/tmp/key.pub"}, false, verifier, nil, bundleDir, nil)

	output := outBuf.String()
	if strings.Contains(output, "Saved") {
		t.Errorf("should not save bundles when signatures fail, got:\n%s", output)
	}
}

// writeLockfileHelper writes a lockfile as JSON to path.
func writeLockfileHelper(t *testing.T, path string, lf *config.Lockfile) {
	t.Helper()
	data, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		t.Fatalf("marshaling lockfile: %v", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}
}
