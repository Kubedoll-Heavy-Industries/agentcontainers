package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/orgpolicy"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/signing"
)

// mockContainerBuilder implements ContainerBuilder for testing.
type mockContainerBuilder struct {
	buildResult *BuildImageResult
	buildErr    error
	pushDigest  string
	pushErr     error
	buildCalled bool
	pushCalled  bool
}

func (m *mockContainerBuilder) Build(_ context.Context, _ *config.AgentContainer, _ BuildImageOptions) (*BuildImageResult, error) {
	m.buildCalled = true
	if m.buildErr != nil {
		return nil, m.buildErr
	}
	return m.buildResult, nil
}

func (m *mockContainerBuilder) Push(_ context.Context, _ string) (string, error) {
	m.pushCalled = true
	if m.pushErr != nil {
		return "", m.pushErr
	}
	return m.pushDigest, nil
}

// mockPolicyInjector implements PolicyInjector for testing.
type mockPolicyInjector struct {
	manifestDigest string
	err            error
	called         bool
	capturedJSON   []byte
}

// mockPolicyExtractor implements PolicyExtractor for testing.
type mockPolicyExtractor struct {
	policy *orgpolicy.OrgPolicy
	err    error
}

func (m *mockPolicyExtractor) ExtractPolicy(_ context.Context, _ string) (*orgpolicy.OrgPolicy, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.policy != nil {
		return m.policy, nil
	}
	return orgpolicy.DefaultPolicy(), nil
}

func (m *mockPolicyInjector) AppendPolicyLayer(_ context.Context, _ string, policyJSON []byte, _ ed25519.PrivateKey) (string, error) {
	m.called = true
	m.capturedJSON = policyJSON
	if m.err != nil {
		return "", m.err
	}
	return m.manifestDigest, nil
}

func TestBuildFlagDefaults(t *testing.T) {
	cmd := newBuildCmd()

	tests := []struct {
		name      string
		flag      string
		defValue  string
		shorthand string
	}{
		{"config", "config", "", "c"},
		{"tag", "tag", "", "t"},
		{"sign", "sign", "false", ""},
		{"key", "key", "", ""},
		{"push", "push", "false", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := cmd.Flags().Lookup(tt.flag)
			if f == nil {
				t.Fatalf("expected --%s flag", tt.flag)
			}
			if f.DefValue != tt.defValue {
				t.Errorf("--%s default = %q, want %q", tt.flag, f.DefValue, tt.defValue)
			}
			if tt.shorthand != "" && f.Shorthand != tt.shorthand {
				t.Errorf("--%s shorthand = %q, want %q", tt.flag, f.Shorthand, tt.shorthand)
			}
		})
	}
}

func TestBuildHelpText(t *testing.T) {
	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"build", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("build --help failed: %v", err)
	}

	output := outBuf.String()
	for _, want := range []string{"--config", "--tag", "--sign", "--key", "--push", "--policy", "Dockerfile"} {
		if !strings.Contains(output, want) {
			t.Errorf("expected %q in help text, got:\n%s", want, output)
		}
	}
}

func TestBuildNoBuildSection(t *testing.T) {
	dir := t.TempDir()

	// Config with image but no build section.
	configContent := `{"name": "test", "image": "alpine:3"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"build", "--config", configPath})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for config without build section")
	}
	if !strings.Contains(err.Error(), "no 'build' section") {
		t.Errorf("expected 'no build section' in error, got: %v", err)
	}
}

func TestBuildSignWithoutPush(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "test", "build": {"dockerfile": "Dockerfile"}}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"build", "--config", configPath, "--sign"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for --sign without --push")
	}
	if !strings.Contains(err.Error(), "--sign requires --push") {
		t.Errorf("expected '--sign requires --push' in error, got: %v", err)
	}
}

func TestBuildSuccess(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "myapp", "build": {"dockerfile": "Dockerfile"}}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	builder := &mockContainerBuilder{
		buildResult: &BuildImageResult{
			ImageID: "sha256:abc123",
			Tag:     "myapp:latest",
		},
	}

	var outBuf bytes.Buffer
	cmd := newBuildCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"--config", configPath})

	// Use the testable function directly.
	err := runBuildWithDeps(cmd, configPath, "", false, "", false, "", "", false, builder, nil, nil, nil)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	if !builder.buildCalled {
		t.Error("builder.Build was not called")
	}
	if builder.pushCalled {
		t.Error("builder.Push should not be called without --push")
	}

	output := outBuf.String()
	if !strings.Contains(output, "Built image: myapp:latest") {
		t.Errorf("expected 'Built image: myapp:latest' in output, got:\n%s", output)
	}
}

func TestBuildWithCustomTag(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "myapp", "build": {"dockerfile": "Dockerfile"}}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	builder := &mockContainerBuilder{
		buildResult: &BuildImageResult{
			ImageID: "sha256:abc123",
			Tag:     "myregistry.io/app:v2",
		},
	}

	var outBuf bytes.Buffer
	cmd := newBuildCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runBuildWithDeps(cmd, configPath, "myregistry.io/app:v2", false, "", false, "", "", false, builder, nil, nil, nil)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "Building image myregistry.io/app:v2") {
		t.Errorf("expected custom tag in output, got:\n%s", output)
	}
}

func TestBuildDefaultTagNoName(t *testing.T) {
	dir := t.TempDir()

	// Config without a name.
	configContent := `{"build": {"dockerfile": "Dockerfile"}}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	builder := &mockContainerBuilder{
		buildResult: &BuildImageResult{
			ImageID: "sha256:abc123",
			Tag:     "agentcontainer:latest",
		},
	}

	var outBuf bytes.Buffer
	cmd := newBuildCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runBuildWithDeps(cmd, configPath, "", false, "", false, "", "", false, builder, nil, nil, nil)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "agentcontainer:latest") {
		t.Errorf("expected default tag 'agentcontainer:latest' in output, got:\n%s", output)
	}
}

func TestBuildWithPush(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "myapp", "build": {"dockerfile": "Dockerfile"}}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	builder := &mockContainerBuilder{
		buildResult: &BuildImageResult{
			ImageID: "sha256:abc123",
			Tag:     "myapp:latest",
		},
		pushDigest: "sha256:def456",
	}

	var outBuf bytes.Buffer
	cmd := newBuildCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runBuildWithDeps(cmd, configPath, "", false, "", true, "", "", false, builder, nil, nil, nil)
	if err != nil {
		t.Fatalf("build with push failed: %v", err)
	}

	if !builder.pushCalled {
		t.Error("builder.Push was not called with --push")
	}

	output := outBuf.String()
	if !strings.Contains(output, "Pushed: myapp:latest@sha256:def456") {
		t.Errorf("expected push output, got:\n%s", output)
	}
}

func TestBuildWithPushAndSign(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "myapp", "build": {"dockerfile": "Dockerfile"}}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	builder := &mockContainerBuilder{
		buildResult: &BuildImageResult{
			ImageID: "sha256:abc123",
			Tag:     "myapp:latest",
		},
		pushDigest: "sha256:def456",
	}

	signer := signing.NewMockSigner()

	var outBuf bytes.Buffer
	cmd := newBuildCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runBuildWithDeps(cmd, configPath, "", true, "", true, "", "", false, builder, nil, signer, nil)
	if err != nil {
		t.Fatalf("build with sign failed: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "Signing") {
		t.Errorf("expected signing output, got:\n%s", output)
	}
	if !strings.Contains(output, "Signed:") {
		t.Errorf("expected 'Signed:' in output, got:\n%s", output)
	}
}

func TestBuildBuildError(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "myapp", "build": {"dockerfile": "Dockerfile"}}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	builder := &mockContainerBuilder{
		buildErr: fmt.Errorf("docker daemon not running"),
	}

	var outBuf bytes.Buffer
	cmd := newBuildCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runBuildWithDeps(cmd, configPath, "", false, "", false, "", "", false, builder, nil, nil, nil)
	if err == nil {
		t.Fatal("expected build error")
	}
	if !strings.Contains(err.Error(), "docker daemon not running") {
		t.Errorf("expected 'docker daemon not running' in error, got: %v", err)
	}
}

func TestBuildPushError(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "myapp", "build": {"dockerfile": "Dockerfile"}}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	builder := &mockContainerBuilder{
		buildResult: &BuildImageResult{
			ImageID: "sha256:abc123",
			Tag:     "myapp:latest",
		},
		pushErr: fmt.Errorf("unauthorized"),
	}

	var outBuf bytes.Buffer
	cmd := newBuildCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runBuildWithDeps(cmd, configPath, "", false, "", true, "", "", false, builder, nil, nil, nil)
	if err == nil {
		t.Fatal("expected push error")
	}
	if !strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("expected 'unauthorized' in error, got: %v", err)
	}
}

func TestBuildSignError(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "myapp", "build": {"dockerfile": "Dockerfile"}}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	builder := &mockContainerBuilder{
		buildResult: &BuildImageResult{
			ImageID: "sha256:abc123",
			Tag:     "myapp:latest",
		},
		pushDigest: "sha256:def456",
	}

	// Use a signer that always fails.
	failSigner := signing.NewCosignSigner(signing.WithSignFunc(
		func(_ context.Context, _ string, _ signing.SignOptions) (*signing.SignResult, error) {
			return nil, fmt.Errorf("OIDC token expired")
		},
	))

	var outBuf bytes.Buffer
	cmd := newBuildCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runBuildWithDeps(cmd, configPath, "", true, "", true, "", "", false, builder, nil, failSigner, nil)
	if err == nil {
		t.Fatal("expected signing error")
	}
	if !strings.Contains(err.Error(), "OIDC token expired") {
		t.Errorf("expected 'OIDC token expired' in error, got: %v", err)
	}
}

func TestBuildMissingConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "nonexistent.json")

	var outBuf bytes.Buffer
	cmd := newBuildCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runBuildWithDeps(cmd, configPath, "", false, "", false, "", "", false, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for missing config")
	}
}

func TestBuildPolicyWithoutPush(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "myapp", "build": {"dockerfile": "Dockerfile"}}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	policyContent := `{"requireSignatures": true}`
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(policyContent), 0o644); err != nil {
		t.Fatal(err)
	}

	var outBuf bytes.Buffer
	cmd := newBuildCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runBuildWithDeps(cmd, configPath, "", false, "", false, policyPath, "", false, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for --policy without --push")
	}
	if !strings.Contains(err.Error(), "--policy requires --push") {
		t.Errorf("expected '--policy requires --push' in error, got: %v", err)
	}
}

func TestBuildWithPolicy(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "myapp", "build": {"dockerfile": "Dockerfile"}}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	policyContent := `{"requireSignatures": true, "minSLSALevel": 2}`
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(policyContent), 0o644); err != nil {
		t.Fatal(err)
	}

	builder := &mockContainerBuilder{
		buildResult: &BuildImageResult{
			ImageID: "sha256:abc123",
			Tag:     "myapp:latest",
		},
		pushDigest: "sha256:def456",
	}

	injector := &mockPolicyInjector{
		manifestDigest: "sha256:withpolicy789",
	}

	var outBuf bytes.Buffer
	cmd := newBuildCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	extractor := &mockPolicyExtractor{}
	err := runBuildWithDeps(cmd, configPath, "", false, "", true, policyPath, "", false, builder, injector, nil, extractor)
	if err != nil {
		t.Fatalf("build with policy failed: %v", err)
	}

	if !injector.called {
		t.Error("PolicyInjector.AppendPolicyLayer was not called")
	}

	output := outBuf.String()
	if !strings.Contains(output, "Injecting policy layer") {
		t.Errorf("expected 'Injecting policy layer' in output, got:\n%s", output)
	}
	if !strings.Contains(output, "sha256:withpolicy789") {
		t.Errorf("expected policy manifest digest in output, got:\n%s", output)
	}
}

func TestBuildWithPolicyInvalidJSON(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "myapp", "build": {"dockerfile": "Dockerfile"}}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Invalid policy — SLSA level 99 out of range.
	policyContent := `{"minSLSALevel": 99}`
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(policyContent), 0o644); err != nil {
		t.Fatal(err)
	}

	var outBuf bytes.Buffer
	cmd := newBuildCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runBuildWithDeps(cmd, configPath, "", false, "", true, policyPath, "", false, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid policy")
	}
	if !strings.Contains(err.Error(), "--policy") {
		t.Errorf("expected '--policy' in error, got: %v", err)
	}
}

func TestBuildWithPolicyInjectorError(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "myapp", "build": {"dockerfile": "Dockerfile"}}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	policyContent := `{"requireSignatures": true}`
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(policyContent), 0o644); err != nil {
		t.Fatal(err)
	}

	builder := &mockContainerBuilder{
		buildResult: &BuildImageResult{
			ImageID: "sha256:abc123",
			Tag:     "myapp:latest",
		},
		pushDigest: "sha256:def456",
	}

	injector := &mockPolicyInjector{
		err: fmt.Errorf("registry unavailable"),
	}

	var outBuf bytes.Buffer
	cmd := newBuildCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	extractor := &mockPolicyExtractor{}
	err := runBuildWithDeps(cmd, configPath, "", false, "", true, policyPath, "", false, builder, injector, nil, extractor)
	if err == nil {
		t.Fatal("expected error from policy injector")
	}
	if !strings.Contains(err.Error(), "registry unavailable") {
		t.Errorf("expected 'registry unavailable' in error, got: %v", err)
	}
}

func TestBuildWithPolicyAndSign(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "myapp", "build": {"dockerfile": "Dockerfile"}}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	policyContent := `{"requireSignatures": true}`
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(policyContent), 0o644); err != nil {
		t.Fatal(err)
	}

	builder := &mockContainerBuilder{
		buildResult: &BuildImageResult{
			ImageID: "sha256:abc123",
			Tag:     "myapp:latest",
		},
		pushDigest: "sha256:def456",
	}

	// Injector returns the final manifest digest (with policy layer).
	injector := &mockPolicyInjector{
		manifestDigest: "sha256:withpolicy789",
	}

	signer := signing.NewMockSigner()

	var outBuf bytes.Buffer
	cmd := newBuildCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	extractor := &mockPolicyExtractor{}
	err := runBuildWithDeps(cmd, configPath, "", true, "", true, policyPath, "", false, builder, injector, signer, extractor)
	if err != nil {
		t.Fatalf("build with policy and sign failed: %v", err)
	}

	output := outBuf.String()
	// The signing ref should use the policy manifest digest, not the push digest.
	if !strings.Contains(output, "sha256:withpolicy789") {
		t.Errorf("expected policy manifest digest in signing output, got:\n%s", output)
	}
	if !strings.Contains(output, "Signing") {
		t.Errorf("expected 'Signing' in output, got:\n%s", output)
	}
}

func TestBuildPolicyWeakeningRejected(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "myapp", "build": {"dockerfile": "Dockerfile"}}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Candidate policy drops requireSignatures that is already baked into the image.
	candidateContent := `{"requireSignatures": false, "minSLSALevel": 1}`
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(candidateContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Existing image has a stricter policy.
	extractor := &mockPolicyExtractor{
		policy: &orgpolicy.OrgPolicy{
			RequireSignatures: true,
			MinSLSALevel:      2,
		},
	}

	var outBuf bytes.Buffer
	cmd := newBuildCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runBuildWithDeps(cmd, configPath, "", false, "", true, policyPath, "", false, nil, nil, nil, extractor)
	if err == nil {
		t.Fatal("expected error: candidate policy weakens existing policy")
	}
	if !strings.Contains(err.Error(), "weakens") {
		t.Errorf("expected 'weakens' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "requireSignatures") {
		t.Errorf("expected 'requireSignatures' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "minSLSALevel") {
		t.Errorf("expected 'minSLSALevel' in error, got: %v", err)
	}
}

func TestBuildPolicyWeakeningPassesWhenStricter(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "myapp", "build": {"dockerfile": "Dockerfile"}}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Candidate tightens the policy relative to what's baked in.
	candidateContent := `{"requireSignatures": true, "minSLSALevel": 3}`
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(candidateContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Existing image has a looser policy.
	extractor := &mockPolicyExtractor{
		policy: &orgpolicy.OrgPolicy{
			RequireSignatures: false,
			MinSLSALevel:      1,
		},
	}

	builder := &mockContainerBuilder{
		buildResult: &BuildImageResult{
			ImageID: "sha256:abc123",
			Tag:     "myapp:latest",
		},
		pushDigest: "sha256:def456",
	}
	injector := &mockPolicyInjector{manifestDigest: "sha256:withpolicy789"}

	var outBuf bytes.Buffer
	cmd := newBuildCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runBuildWithDeps(cmd, configPath, "", false, "", true, policyPath, "", false, builder, injector, nil, extractor)
	if err != nil {
		t.Fatalf("expected no error for stricter policy, got: %v", err)
	}
}

func TestBuildPolicyExtractorError(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "myapp", "build": {"dockerfile": "Dockerfile"}}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	policyContent := `{"requireSignatures": true}`
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(policyContent), 0o644); err != nil {
		t.Fatal(err)
	}

	extractor := &mockPolicyExtractor{
		err: fmt.Errorf("registry unreachable"),
	}

	var outBuf bytes.Buffer
	cmd := newBuildCmd()
	cmd.SetOut(&outBuf)
	cmd.SetContext(context.Background())

	err := runBuildWithDeps(cmd, configPath, "", false, "", true, policyPath, "", false, nil, nil, nil, extractor)
	if err == nil {
		t.Fatal("expected error from extractor")
	}
	if !strings.Contains(err.Error(), "registry unreachable") {
		t.Errorf("expected 'registry unreachable' in error, got: %v", err)
	}
}

func TestParseBuildOutput(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantID  string
		wantErr bool
	}{
		{
			name:   "with aux ID",
			input:  `{"stream":"Step 1/2 : FROM alpine"}` + "\n" + `{"aux":{"ID":"sha256:abc123"}}` + "\n",
			wantID: "sha256:abc123",
		},
		{
			name:    "with error",
			input:   `{"error":"Dockerfile not found"}` + "\n",
			wantErr: true,
		},
		{
			name:   "empty stream",
			input:  `{"stream":"done"}` + "\n",
			wantID: "sha256:unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := parseBuildOutput(strings.NewReader(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("parseBuildOutput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && id != tt.wantID {
				t.Errorf("parseBuildOutput() = %q, want %q", id, tt.wantID)
			}
		})
	}
}

func TestParsePushOutput(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantDigest string
		wantErr    bool
	}{
		{
			name:       "with digest",
			input:      `{"status":"Pushing"}` + "\n" + `{"aux":{"Digest":"sha256:def456"}}` + "\n",
			wantDigest: "sha256:def456",
		},
		{
			name:    "with error",
			input:   `{"error":"unauthorized"}` + "\n",
			wantErr: true,
		},
		{
			name:    "no digest",
			input:   `{"status":"done"}` + "\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest, err := parsePushOutput(strings.NewReader(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePushOutput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && digest != tt.wantDigest {
				t.Errorf("parsePushOutput() = %q, want %q", digest, tt.wantDigest)
			}
		})
	}
}
