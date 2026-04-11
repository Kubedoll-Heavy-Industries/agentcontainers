package signing

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCosignVerifierValidatesEmptyRef(t *testing.T) {
	v := NewCosignVerifier()
	_, err := v.Verify(context.Background(), "", VerifyOptions{})
	if err == nil {
		t.Fatal("expected error for empty ref")
	}
	if !strings.Contains(err.Error(), "empty artifact reference") {
		t.Errorf("expected 'empty artifact reference' in error, got: %v", err)
	}
}

func TestCosignVerifierMutuallyExclusiveKeyAndKeyless(t *testing.T) {
	v := NewCosignVerifier()
	_, err := v.Verify(context.Background(), "registry.io/image@sha256:abc", VerifyOptions{
		KeyPath:      "/tmp/key.pub",
		CertIdentity: "user@example.com",
	})
	if err == nil {
		t.Fatal("expected error for mutually exclusive key and keyless")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected 'mutually exclusive' in error, got: %v", err)
	}
}

func TestCosignVerifierKeylessRequiresBoth(t *testing.T) {
	tests := []struct {
		name string
		opts VerifyOptions
	}{
		{
			name: "identity without issuer",
			opts: VerifyOptions{CertIdentity: "user@example.com"},
		},
		{
			name: "issuer without identity",
			opts: VerifyOptions{CertIssuer: "https://accounts.google.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewCosignVerifier()
			_, err := v.Verify(context.Background(), "registry.io/image@sha256:abc", tt.opts)
			if err == nil {
				t.Fatal("expected error for incomplete keyless config")
			}
			if !strings.Contains(err.Error(), "requires both cert-identity and cert-issuer") {
				t.Errorf("expected 'requires both' in error, got: %v", err)
			}
		})
	}
}

func TestCosignVerifierReturnsNotConfiguredWhenBinaryMissing(t *testing.T) {
	if _, err := lookPath("cosign"); err == nil {
		t.Skip("cosign binary is present on PATH; skipping binary-missing test")
	}
	v := NewCosignVerifier()
	_, err := v.Verify(context.Background(), "registry.io/image@sha256:abc", VerifyOptions{})
	if err == nil {
		t.Fatal("expected error when cosign binary is not available")
	}
	if !errors.Is(err, ErrVerifyNotConfigured) {
		t.Errorf("expected ErrVerifyNotConfigured, got: %v", err)
	}
}

func TestCosignVerifierWithVerifyFunc(t *testing.T) {
	ref := "registry.io/myimage@sha256:deadbeef"
	called := false

	v := NewCosignVerifier(WithVerifyFunc(func(_ context.Context, gotRef string, _ VerifyOptions) (*VerifyResult, error) {
		called = true
		if gotRef != ref {
			t.Errorf("expected ref %q, got %q", ref, gotRef)
		}
		return &VerifyResult{
			Verified:       true,
			SignerIdentity: "test@example.com",
			RekorLogIndex:  99,
		}, nil
	}))

	result, err := v.Verify(context.Background(), ref, VerifyOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("verify function was not called")
	}
	if !result.Verified {
		t.Error("expected verified=true")
	}
	if result.SignerIdentity != "test@example.com" {
		t.Errorf("expected signer identity 'test@example.com', got %s", result.SignerIdentity)
	}
}

func TestCosignVerifierWithVerifyFuncError(t *testing.T) {
	wantErr := errors.New("no signatures found")
	v := NewCosignVerifier(WithVerifyFunc(func(_ context.Context, _ string, _ VerifyOptions) (*VerifyResult, error) {
		return nil, wantErr
	}))

	_, err := v.Verify(context.Background(), "registry.io/image@sha256:abc", VerifyOptions{})
	if err == nil {
		t.Fatal("expected error from verify function")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("expected wrapped error %v, got: %v", wantErr, err)
	}
}

func TestNewMockVerifier(t *testing.T) {
	v := NewMockVerifier()
	ref := "registry.io/image@sha256:abc123"

	result, err := v.Verify(context.Background(), ref, VerifyOptions{})
	if err != nil {
		t.Fatalf("mock verifier should succeed: %v", err)
	}
	if !result.Verified {
		t.Error("expected verified=true")
	}
}

func TestNewMockVerifierKeyless(t *testing.T) {
	v := NewMockVerifier()
	ref := "registry.io/image@sha256:abc123"

	result, err := v.Verify(context.Background(), ref, VerifyOptions{
		CertIdentity: "user@example.com",
		CertIssuer:   "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("mock verifier should succeed: %v", err)
	}
	if !result.Verified {
		t.Error("expected verified=true")
	}
	if result.SignerIdentity != "user@example.com" {
		t.Errorf("expected signer identity 'user@example.com', got %s", result.SignerIdentity)
	}
	if result.RekorLogIndex < 0 {
		t.Error("expected positive rekor log index for keyless")
	}
}

func TestNewMockVerifierFailing(t *testing.T) {
	v := NewMockVerifierFailing()
	ref := "registry.io/image@sha256:abc123"

	_, err := v.Verify(context.Background(), ref, VerifyOptions{})
	if err == nil {
		t.Fatal("expected error from failing mock verifier")
	}
	if !strings.Contains(err.Error(), "no valid signatures") {
		t.Errorf("expected 'no valid signatures' in error, got: %v", err)
	}
}

func TestVerifyAcceptsTagRef(t *testing.T) {
	v := NewMockVerifier()
	// Verify should accept tagged refs (not just digest refs).
	result, err := v.Verify(context.Background(), "registry.io/image:latest", VerifyOptions{})
	if err != nil {
		t.Fatalf("verify should accept tagged refs: %v", err)
	}
	if !result.Verified {
		t.Error("expected verified=true")
	}
}

func TestBuildVerifyArgsKeyBased(t *testing.T) {
	ref := "registry.io/image@sha256:abc123"
	opts := VerifyOptions{
		KeyPath: "/tmp/cosign.pub",
	}
	args := buildVerifyArgs(ref, opts)
	expected := []string{"verify", "--key", "/tmp/cosign.pub", ref}
	if len(args) != len(expected) {
		t.Fatalf("expected %d args, got %d: %v", len(expected), len(args), args)
	}
	for i, v := range expected {
		if args[i] != v {
			t.Errorf("arg[%d] = %q, want %q", i, args[i], v)
		}
	}
}

func TestBuildVerifyArgsKeyless(t *testing.T) {
	ref := "registry.io/image@sha256:abc123"
	opts := VerifyOptions{
		CertIdentity: "user@example.com",
		CertIssuer:   "https://accounts.google.com",
	}
	args := buildVerifyArgs(ref, opts)
	expected := []string{
		"verify",
		"--certificate-identity", "user@example.com",
		"--certificate-oidc-issuer", "https://accounts.google.com",
		ref,
	}
	if len(args) != len(expected) {
		t.Fatalf("expected %d args, got %d: %v", len(expected), len(args), args)
	}
	for i, v := range expected {
		if args[i] != v {
			t.Errorf("arg[%d] = %q, want %q", i, args[i], v)
		}
	}
}

func TestBuildVerifyArgsWithRekorURL(t *testing.T) {
	ref := "registry.io/image@sha256:abc123"
	opts := VerifyOptions{
		KeyPath:  "/tmp/cosign.pub",
		RekorURL: "https://rekor.example.com",
	}
	args := buildVerifyArgs(ref, opts)
	found := false
	for i, a := range args {
		if a == "--rekor-url" && i+1 < len(args) && args[i+1] == "https://rekor.example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected --rekor-url in args: %v", args)
	}
}

func TestBuildVerifyEnvKeyless(t *testing.T) {
	env := buildVerifyEnv(VerifyOptions{})
	found := false
	for _, e := range env {
		if e == "COSIGN_EXPERIMENTAL=1" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected COSIGN_EXPERIMENTAL=1 for keyless verification without cert options")
	}
}

func TestBuildVerifyEnvKeyBased(t *testing.T) {
	env := buildVerifyEnv(VerifyOptions{KeyPath: "/tmp/cosign.pub"})
	for _, e := range env {
		if e == "COSIGN_EXPERIMENTAL=1" {
			t.Error("should not set COSIGN_EXPERIMENTAL for key-based verification")
		}
	}
}

func TestBuildVerifyEnvWithCertIdentity(t *testing.T) {
	env := buildVerifyEnv(VerifyOptions{
		CertIdentity: "user@example.com",
		CertIssuer:   "https://accounts.google.com",
	})
	for _, e := range env {
		if e == "COSIGN_EXPERIMENTAL=1" {
			t.Error("should not set COSIGN_EXPERIMENTAL when cert identity is provided")
		}
	}
}

func TestExecVerifySuccess(t *testing.T) {
	origLookPath := lookPath
	lookPath = func(file string) (string, error) { return "/usr/bin/cosign", nil }
	t.Cleanup(func() { lookPath = origLookPath })

	var capturedName string
	var capturedArgs []string
	runner := &fakeCmdRunner{
		runFn: func(_ context.Context, name string, args []string, _ []string) ([]byte, error) {
			capturedName = name
			capturedArgs = args
			return []byte(`[{"critical":{"identity":{}}}]`), nil
		},
	}

	v := NewCosignVerifier(withVerifyRunner(runner))
	ref := "registry.io/image@sha256:abc123"
	result, err := v.Verify(context.Background(), ref, VerifyOptions{KeyPath: "/tmp/cosign.pub"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedName != "cosign" {
		t.Errorf("expected command 'cosign', got %q", capturedName)
	}
	if capturedArgs[0] != "verify" {
		t.Errorf("expected first arg 'verify', got %q", capturedArgs[0])
	}
	if !result.Verified {
		t.Error("expected verified=true")
	}
	if result.SignerIdentity != "key:/tmp/cosign.pub" {
		t.Errorf("expected signer identity 'key:/tmp/cosign.pub', got %q", result.SignerIdentity)
	}
}

func TestExecVerifyKeyless(t *testing.T) {
	origLookPath := lookPath
	lookPath = func(file string) (string, error) { return "/usr/bin/cosign", nil }
	t.Cleanup(func() { lookPath = origLookPath })

	var capturedArgs []string
	runner := &fakeCmdRunner{
		runFn: func(_ context.Context, _ string, args []string, _ []string) ([]byte, error) {
			capturedArgs = args
			return []byte(`[{"optional":{"Issuer":"https://accounts.google.com","Subject":"user@example.com"}}]`), nil
		},
	}

	v := NewCosignVerifier(withVerifyRunner(runner))
	ref := "registry.io/image@sha256:abc123"
	result, err := v.Verify(context.Background(), ref, VerifyOptions{
		CertIdentity: "user@example.com",
		CertIssuer:   "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Check that --certificate-identity and --certificate-oidc-issuer are in args.
	foundIdent := false
	foundIssuer := false
	for i, a := range capturedArgs {
		if a == "--certificate-identity" && i+1 < len(capturedArgs) && capturedArgs[i+1] == "user@example.com" {
			foundIdent = true
		}
		if a == "--certificate-oidc-issuer" && i+1 < len(capturedArgs) && capturedArgs[i+1] == "https://accounts.google.com" {
			foundIssuer = true
		}
	}
	if !foundIdent {
		t.Errorf("expected --certificate-identity in args: %v", capturedArgs)
	}
	if !foundIssuer {
		t.Errorf("expected --certificate-oidc-issuer in args: %v", capturedArgs)
	}
	if !result.Verified {
		t.Error("expected verified=true")
	}
	if result.SignerIdentity != "user@example.com" {
		t.Errorf("expected signer identity 'user@example.com', got %q", result.SignerIdentity)
	}
	if result.IssuerURL != "https://accounts.google.com" {
		t.Errorf("expected issuer URL 'https://accounts.google.com', got %q", result.IssuerURL)
	}
	if result.RekorLogIndex != 0 {
		t.Errorf("expected rekor log index 0 for keyless, got %d", result.RekorLogIndex)
	}
}

func TestExecVerifyFailure(t *testing.T) {
	origLookPath := lookPath
	lookPath = func(file string) (string, error) { return "/usr/bin/cosign", nil }
	t.Cleanup(func() { lookPath = origLookPath })

	runner := &fakeCmdRunner{
		runFn: func(_ context.Context, _ string, _ []string, _ []string) ([]byte, error) {
			return nil, errors.New("cosign failed: exit status 1: no matching signatures")
		},
	}

	v := NewCosignVerifier(withVerifyRunner(runner))
	_, err := v.Verify(context.Background(), "registry.io/image@sha256:abc123", VerifyOptions{})
	if err == nil {
		t.Fatal("expected error from failed cosign command")
	}
	if !strings.Contains(err.Error(), "cosign verify") {
		t.Errorf("expected 'cosign verify' in error, got: %v", err)
	}
}
