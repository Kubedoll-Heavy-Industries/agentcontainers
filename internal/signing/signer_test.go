package signing

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCosignSignerValidatesEmptyRef(t *testing.T) {
	s := NewCosignSigner()
	_, err := s.Sign(context.Background(), "", SignOptions{})
	if err == nil {
		t.Fatal("expected error for empty ref")
	}
	if !strings.Contains(err.Error(), "empty artifact reference") {
		t.Errorf("expected 'empty artifact reference' in error, got: %v", err)
	}
}

func TestCosignSignerValidatesDigestInRef(t *testing.T) {
	s := NewCosignSigner()
	_, err := s.Sign(context.Background(), "registry.io/image:latest", SignOptions{})
	if err == nil {
		t.Fatal("expected error for ref without digest")
	}
	if !strings.Contains(err.Error(), "must include a digest") {
		t.Errorf("expected 'must include a digest' in error, got: %v", err)
	}
}

func TestCosignSignerMutuallyExclusiveKeyAndKeyless(t *testing.T) {
	s := NewCosignSigner()
	_, err := s.Sign(context.Background(), "registry.io/image@sha256:abc", SignOptions{
		KeyPath:       "/tmp/key.pem",
		KeylessIssuer: "https://accounts.google.com",
	})
	if err == nil {
		t.Fatal("expected error for mutually exclusive key and keyless")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected 'mutually exclusive' in error, got: %v", err)
	}
}

func TestCosignSignerKeylessRequiresBoth(t *testing.T) {
	tests := []struct {
		name string
		opts SignOptions
	}{
		{
			name: "issuer without identity",
			opts: SignOptions{KeylessIssuer: "https://accounts.google.com"},
		},
		{
			name: "identity without issuer",
			opts: SignOptions{KeylessIdentity: "user@example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewCosignSigner()
			_, err := s.Sign(context.Background(), "registry.io/image@sha256:abc", tt.opts)
			if err == nil {
				t.Fatal("expected error for incomplete keyless config")
			}
			if !strings.Contains(err.Error(), "requires both issuer and identity") {
				t.Errorf("expected 'requires both issuer and identity' in error, got: %v", err)
			}
		})
	}
}

func TestCosignSignerReturnsNotConfiguredWhenBinaryMissing(t *testing.T) {
	if _, err := lookPath("cosign"); err == nil {
		t.Skip("cosign binary is present on PATH; skipping binary-missing test")
	}
	s := NewCosignSigner()
	_, err := s.Sign(context.Background(), "registry.io/image@sha256:abc123", SignOptions{})
	if err == nil {
		t.Fatal("expected error when cosign binary is not available")
	}
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("expected ErrNotConfigured, got: %v", err)
	}
}

func TestCosignSignerWithSignFunc(t *testing.T) {
	ref := "registry.io/myimage@sha256:deadbeef"
	called := false

	s := NewCosignSigner(WithSignFunc(func(_ context.Context, gotRef string, opts SignOptions) (*SignResult, error) {
		called = true
		if gotRef != ref {
			t.Errorf("expected ref %q, got %q", ref, gotRef)
		}
		return &SignResult{
			Ref:             gotRef,
			Digest:          "sha256:deadbeef",
			SignatureDigest: "sha256:sig123",
			RekorLogIndex:   42,
		}, nil
	}))

	result, err := s.Sign(context.Background(), ref, SignOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("sign function was not called")
	}
	if result.Digest != "sha256:deadbeef" {
		t.Errorf("expected digest sha256:deadbeef, got %s", result.Digest)
	}
	if result.RekorLogIndex != 42 {
		t.Errorf("expected rekor log index 42, got %d", result.RekorLogIndex)
	}
}

func TestCosignSignerWithSignFuncError(t *testing.T) {
	wantErr := errors.New("signing backend failure")
	s := NewCosignSigner(WithSignFunc(func(_ context.Context, _ string, _ SignOptions) (*SignResult, error) {
		return nil, wantErr
	}))

	_, err := s.Sign(context.Background(), "registry.io/image@sha256:abc", SignOptions{})
	if err == nil {
		t.Fatal("expected error from sign function")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("expected wrapped error %v, got: %v", wantErr, err)
	}
}

func TestNewMockSigner(t *testing.T) {
	s := NewMockSigner()
	ref := "registry.io/image@sha256:abc123"

	result, err := s.Sign(context.Background(), ref, SignOptions{})
	if err != nil {
		t.Fatalf("mock signer should succeed: %v", err)
	}
	if result.Ref != ref {
		t.Errorf("expected ref %q, got %q", ref, result.Ref)
	}
	if result.Digest != "sha256:abc123" {
		t.Errorf("expected digest sha256:abc123, got %s", result.Digest)
	}
	if result.RekorLogIndex != -1 {
		t.Errorf("expected rekor log index -1 for key-based, got %d", result.RekorLogIndex)
	}
}

func TestNewMockSignerKeyless(t *testing.T) {
	s := NewMockSigner()
	ref := "registry.io/image@sha256:abc123"

	result, err := s.Sign(context.Background(), ref, SignOptions{
		KeylessIssuer:   "https://accounts.google.com",
		KeylessIdentity: "user@example.com",
	})
	if err != nil {
		t.Fatalf("mock signer should succeed: %v", err)
	}
	if result.RekorLogIndex < 0 {
		t.Errorf("expected positive rekor log index for keyless, got %d", result.RekorLogIndex)
	}
	if result.Certificate == "" {
		t.Error("expected certificate for keyless signing")
	}
}

func TestBuildSignArgsKeyBased(t *testing.T) {
	ref := "registry.io/image@sha256:abc123"
	opts := SignOptions{
		KeyPath: "/tmp/cosign.key",
	}
	args := buildSignArgs(ref, opts)
	expected := []string{"sign", "--key", "/tmp/cosign.key", "--yes", ref}
	if len(args) != len(expected) {
		t.Fatalf("expected %d args, got %d: %v", len(expected), len(args), args)
	}
	for i, v := range expected {
		if args[i] != v {
			t.Errorf("arg[%d] = %q, want %q", i, args[i], v)
		}
	}
}

func TestBuildSignArgsKeyless(t *testing.T) {
	ref := "registry.io/image@sha256:abc123"
	opts := SignOptions{}
	args := buildSignArgs(ref, opts)
	expected := []string{"sign", "--yes", ref}
	if len(args) != len(expected) {
		t.Fatalf("expected %d args, got %d: %v", len(expected), len(args), args)
	}
	for i, v := range expected {
		if args[i] != v {
			t.Errorf("arg[%d] = %q, want %q", i, args[i], v)
		}
	}
}

func TestBuildSignArgsWithRekorURL(t *testing.T) {
	ref := "registry.io/image@sha256:abc123"
	opts := SignOptions{
		KeyPath:  "/tmp/cosign.key",
		RekorURL: "https://rekor.example.com",
	}
	args := buildSignArgs(ref, opts)
	// Should contain --rekor-url
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

func TestBuildSignArgsWithAnnotations(t *testing.T) {
	ref := "registry.io/image@sha256:abc123"
	opts := SignOptions{
		Annotations: map[string]string{
			"build": "ci",
		},
	}
	args := buildSignArgs(ref, opts)
	found := false
	for i, a := range args {
		if a == "--annotation" && i+1 < len(args) && args[i+1] == "build=ci" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected --annotation build=ci in args: %v", args)
	}
}

func TestBuildSignEnvKeyless(t *testing.T) {
	env := buildSignEnv(SignOptions{})
	found := false
	for _, e := range env {
		if e == "COSIGN_EXPERIMENTAL=1" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected COSIGN_EXPERIMENTAL=1 for keyless signing")
	}
}

func TestBuildSignEnvKeyBased(t *testing.T) {
	env := buildSignEnv(SignOptions{KeyPath: "/tmp/key.pem"})
	for _, e := range env {
		if e == "COSIGN_EXPERIMENTAL=1" {
			t.Error("should not set COSIGN_EXPERIMENTAL for key-based signing")
		}
	}
}

func TestExecSignSuccess(t *testing.T) {
	// Save and restore lookPath.
	origLookPath := lookPath
	lookPath = func(file string) (string, error) { return "/usr/bin/cosign", nil }
	t.Cleanup(func() { lookPath = origLookPath })

	var capturedName string
	var capturedArgs []string
	var capturedEnv []string
	runner := &fakeCmdRunner{
		runFn: func(_ context.Context, name string, args []string, env []string) ([]byte, error) {
			capturedName = name
			capturedArgs = args
			capturedEnv = env
			return []byte("Pushing signature to: registry.io/image\n"), nil
		},
	}

	s := NewCosignSigner(withRunner(runner))
	ref := "registry.io/image@sha256:abc123"
	result, err := s.Sign(context.Background(), ref, SignOptions{KeyPath: "/tmp/cosign.key"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedName != "cosign" {
		t.Errorf("expected command 'cosign', got %q", capturedName)
	}
	if capturedArgs[0] != "sign" {
		t.Errorf("expected first arg 'sign', got %q", capturedArgs[0])
	}
	// Key-based: should not have COSIGN_EXPERIMENTAL.
	for _, e := range capturedEnv {
		if e == "COSIGN_EXPERIMENTAL=1" {
			t.Error("should not set COSIGN_EXPERIMENTAL for key-based signing")
		}
	}
	if result.Ref != ref {
		t.Errorf("expected ref %q, got %q", ref, result.Ref)
	}
	if result.Digest != "sha256:abc123" {
		t.Errorf("expected digest sha256:abc123, got %s", result.Digest)
	}
	if result.RekorLogIndex != -1 {
		t.Errorf("expected rekor log index -1 for key-based, got %d", result.RekorLogIndex)
	}
}

func TestExecSignKeyless(t *testing.T) {
	origLookPath := lookPath
	lookPath = func(file string) (string, error) { return "/usr/bin/cosign", nil }
	t.Cleanup(func() { lookPath = origLookPath })

	var capturedEnv []string
	runner := &fakeCmdRunner{
		runFn: func(_ context.Context, _ string, _ []string, env []string) ([]byte, error) {
			capturedEnv = env
			return nil, nil
		},
	}

	s := NewCosignSigner(withRunner(runner))
	ref := "registry.io/image@sha256:abc123"
	result, err := s.Sign(context.Background(), ref, SignOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	foundExp := false
	for _, e := range capturedEnv {
		if e == "COSIGN_EXPERIMENTAL=1" {
			foundExp = true
		}
	}
	if !foundExp {
		t.Error("expected COSIGN_EXPERIMENTAL=1 for keyless signing")
	}
	if result.RekorLogIndex != 0 {
		t.Errorf("expected rekor log index 0 for keyless, got %d", result.RekorLogIndex)
	}
}

func TestExecSignFailure(t *testing.T) {
	origLookPath := lookPath
	lookPath = func(file string) (string, error) { return "/usr/bin/cosign", nil }
	t.Cleanup(func() { lookPath = origLookPath })

	runner := &fakeCmdRunner{
		runFn: func(_ context.Context, _ string, _ []string, _ []string) ([]byte, error) {
			return nil, errors.New("cosign failed: exit status 1: error signing")
		},
	}

	s := NewCosignSigner(withRunner(runner))
	_, err := s.Sign(context.Background(), "registry.io/image@sha256:abc123", SignOptions{})
	if err == nil {
		t.Fatal("expected error from failed cosign command")
	}
	if !strings.Contains(err.Error(), "cosign sign") {
		t.Errorf("expected 'cosign sign' in error, got: %v", err)
	}
}

func TestValidateRef(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		wantErr bool
	}{
		{"valid with digest", "registry.io/image@sha256:abc123", false},
		{"empty", "", true},
		{"tag only", "registry.io/image:latest", true},
		{"no tag or digest", "registry.io/image", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRef(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRef(%q) error = %v, wantErr %v", tt.ref, err, tt.wantErr)
			}
		})
	}
}
