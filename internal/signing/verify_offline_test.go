package signing

import (
	"context"
	"strings"
	"testing"
)

// --- Offline verification tests ---

func TestValidateVerifyOptionsOfflineRequiresAnchor(t *testing.T) {
	err := validateVerifyOptions(VerifyOptions{Offline: true})
	if err == nil {
		t.Fatal("expected error for offline without trust anchor")
	}
	if !strings.Contains(err.Error(), "offline verification requires") {
		t.Errorf("expected 'offline verification requires' in error, got: %v", err)
	}
}

func TestValidateVerifyOptionsOfflineWithKey(t *testing.T) {
	err := validateVerifyOptions(VerifyOptions{
		Offline: true,
		KeyPath: "/tmp/cosign.pub",
	})
	if err != nil {
		t.Fatalf("offline with key should be valid: %v", err)
	}
}

func TestValidateVerifyOptionsOfflineWithBundle(t *testing.T) {
	err := validateVerifyOptions(VerifyOptions{
		Offline:    true,
		BundlePath: "/tmp/artifact.sigstore.json",
	})
	if err != nil {
		t.Fatalf("offline with bundle should be valid: %v", err)
	}
}

func TestValidateVerifyOptionsOfflineWithTrustedRoot(t *testing.T) {
	err := validateVerifyOptions(VerifyOptions{
		Offline:         true,
		TrustedRootPath: "/tmp/root.json",
	})
	if err != nil {
		t.Fatalf("offline with trusted root should be valid: %v", err)
	}
}

func TestValidateVerifyOptionsOfflineWithCertChain(t *testing.T) {
	err := validateVerifyOptions(VerifyOptions{
		Offline:              true,
		CertificateChainPath: "/tmp/chain.pem",
	})
	if err != nil {
		t.Fatalf("offline with cert chain should be valid: %v", err)
	}
}

func TestValidateVerifyOptionsTrustedRootRequiresOffline(t *testing.T) {
	err := validateVerifyOptions(VerifyOptions{
		TrustedRootPath: "/tmp/root.json",
	})
	if err == nil {
		t.Fatal("expected error for trusted-root without offline")
	}
	if !strings.Contains(err.Error(), "--trusted-root requires --offline") {
		t.Errorf("expected '--trusted-root requires --offline' in error, got: %v", err)
	}
}

func TestValidateVerifyOptionsCertChainRequiresOffline(t *testing.T) {
	err := validateVerifyOptions(VerifyOptions{
		CertificateChainPath: "/tmp/chain.pem",
	})
	if err == nil {
		t.Fatal("expected error for certificate-chain without offline")
	}
	if !strings.Contains(err.Error(), "--certificate-chain requires --offline") {
		t.Errorf("expected '--certificate-chain requires --offline' in error, got: %v", err)
	}
}

func TestBuildVerifyArgsOfflineWithKey(t *testing.T) {
	ref := "registry.io/image@sha256:abc123"
	opts := VerifyOptions{
		Offline: true,
		KeyPath: "/tmp/cosign.pub",
	}
	args := buildVerifyArgs(ref, opts)

	foundOffline := false
	foundIgnoreTlog := false
	for _, a := range args {
		if a == "--offline-verification" {
			foundOffline = true
		}
		if a == "--insecure-ignore-tlog=true" {
			foundIgnoreTlog = true
		}
	}
	if !foundOffline {
		t.Errorf("expected --offline-verification in args: %v", args)
	}
	if !foundIgnoreTlog {
		t.Errorf("expected --insecure-ignore-tlog=true in args (no bundle): %v", args)
	}
}

func TestBuildVerifyArgsOfflineWithBundle(t *testing.T) {
	ref := "registry.io/image@sha256:abc123"
	opts := VerifyOptions{
		Offline:    true,
		KeyPath:    "/tmp/cosign.pub",
		BundlePath: "/tmp/artifact.sigstore.json",
	}
	args := buildVerifyArgs(ref, opts)

	foundOffline := false
	foundBundle := false
	foundIgnoreTlog := false
	for i, a := range args {
		if a == "--offline-verification" {
			foundOffline = true
		}
		if a == "--bundle" && i+1 < len(args) && args[i+1] == "/tmp/artifact.sigstore.json" {
			foundBundle = true
		}
		if a == "--insecure-ignore-tlog=true" {
			foundIgnoreTlog = true
		}
	}
	if !foundOffline {
		t.Errorf("expected --offline-verification in args: %v", args)
	}
	if !foundBundle {
		t.Errorf("expected --bundle in args: %v", args)
	}
	if foundIgnoreTlog {
		t.Errorf("should NOT set --insecure-ignore-tlog when bundle is present: %v", args)
	}
}

func TestBuildVerifyArgsOfflineWithTrustedRoot(t *testing.T) {
	ref := "registry.io/image@sha256:abc123"
	opts := VerifyOptions{
		Offline:         true,
		KeyPath:         "/tmp/cosign.pub",
		TrustedRootPath: "/tmp/root.json",
	}
	args := buildVerifyArgs(ref, opts)

	foundTrustedRoot := false
	for i, a := range args {
		if a == "--trusted-root" && i+1 < len(args) && args[i+1] == "/tmp/root.json" {
			foundTrustedRoot = true
		}
	}
	if !foundTrustedRoot {
		t.Errorf("expected --trusted-root in args: %v", args)
	}
}

func TestBuildVerifyArgsOfflineWithCertChain(t *testing.T) {
	ref := "registry.io/image@sha256:abc123"
	opts := VerifyOptions{
		Offline:              true,
		KeyPath:              "/tmp/cosign.pub",
		CertificateChainPath: "/tmp/chain.pem",
	}
	args := buildVerifyArgs(ref, opts)

	foundCertChain := false
	for i, a := range args {
		if a == "--certificate-chain" && i+1 < len(args) && args[i+1] == "/tmp/chain.pem" {
			foundCertChain = true
		}
	}
	if !foundCertChain {
		t.Errorf("expected --certificate-chain in args: %v", args)
	}
}

func TestBuildVerifyArgsBundleWithoutOffline(t *testing.T) {
	ref := "registry.io/image@sha256:abc123"
	opts := VerifyOptions{
		KeyPath:    "/tmp/cosign.pub",
		BundlePath: "/tmp/artifact.sigstore.json",
	}
	args := buildVerifyArgs(ref, opts)

	foundBundle := false
	foundOffline := false
	for i, a := range args {
		if a == "--bundle" && i+1 < len(args) && args[i+1] == "/tmp/artifact.sigstore.json" {
			foundBundle = true
		}
		if a == "--offline-verification" {
			foundOffline = true
		}
	}
	if !foundBundle {
		t.Errorf("expected --bundle in args: %v", args)
	}
	if foundOffline {
		t.Errorf("should not have --offline-verification without Offline=true: %v", args)
	}
}

func TestBuildVerifyEnvOfflineNoExperimental(t *testing.T) {
	env := buildVerifyEnv(VerifyOptions{Offline: true})
	for _, e := range env {
		if e == "COSIGN_EXPERIMENTAL=1" {
			t.Error("should not set COSIGN_EXPERIMENTAL in offline mode")
		}
	}
}

func TestBuildVerifyEnvOfflineWithTrustedRoot(t *testing.T) {
	env := buildVerifyEnv(VerifyOptions{
		Offline:         true,
		TrustedRootPath: "/tmp/tuf-root",
	})
	foundTufRoot := false
	for _, e := range env {
		if e == "TUF_ROOT=/tmp/tuf-root" {
			foundTufRoot = true
		}
	}
	if !foundTufRoot {
		t.Errorf("expected TUF_ROOT env var, got: %v", env)
	}
}

func TestExecVerifyOfflineWithKey(t *testing.T) {
	origLookPath := lookPath
	lookPath = func(file string) (string, error) { return "/usr/bin/cosign", nil }
	t.Cleanup(func() { lookPath = origLookPath })

	var capturedArgs []string
	runner := &fakeCmdRunner{
		runFn: func(_ context.Context, _ string, args []string, _ []string) ([]byte, error) {
			capturedArgs = args
			return []byte(`[{"optional":{}}]`), nil
		},
	}

	v := NewCosignVerifier(withVerifyRunner(runner))
	ref := "registry.io/image@sha256:abc123"
	result, err := v.Verify(context.Background(), ref, VerifyOptions{
		Offline: true,
		KeyPath: "/tmp/cosign.pub",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Verified {
		t.Error("expected verified=true")
	}
	if !result.Offline {
		t.Error("expected offline=true in result")
	}
	if result.BundleVerified {
		t.Error("expected bundleVerified=false when no bundle provided")
	}

	foundOffline := false
	for _, a := range capturedArgs {
		if a == "--offline-verification" {
			foundOffline = true
		}
	}
	if !foundOffline {
		t.Errorf("expected --offline-verification in args: %v", capturedArgs)
	}
}

func TestExecVerifyOfflineWithBundle(t *testing.T) {
	origLookPath := lookPath
	lookPath = func(file string) (string, error) { return "/usr/bin/cosign", nil }
	t.Cleanup(func() { lookPath = origLookPath })

	var capturedArgs []string
	runner := &fakeCmdRunner{
		runFn: func(_ context.Context, _ string, args []string, _ []string) ([]byte, error) {
			capturedArgs = args
			return []byte(`[{"optional":{}}]`), nil
		},
	}

	v := NewCosignVerifier(withVerifyRunner(runner))
	ref := "registry.io/image@sha256:abc123"
	result, err := v.Verify(context.Background(), ref, VerifyOptions{
		Offline:    true,
		BundlePath: "/tmp/artifact.sigstore.json",
		KeyPath:    "/tmp/cosign.pub",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Verified {
		t.Error("expected verified=true")
	}
	if !result.Offline {
		t.Error("expected offline=true in result")
	}
	if !result.BundleVerified {
		t.Error("expected bundleVerified=true when bundle provided")
	}

	foundBundle := false
	for i, a := range capturedArgs {
		if a == "--bundle" && i+1 < len(capturedArgs) && capturedArgs[i+1] == "/tmp/artifact.sigstore.json" {
			foundBundle = true
		}
	}
	if !foundBundle {
		t.Errorf("expected --bundle in args: %v", capturedArgs)
	}
}

func TestExecVerifyOfflineKeylessRekorIndex(t *testing.T) {
	origLookPath := lookPath
	lookPath = func(file string) (string, error) { return "/usr/bin/cosign", nil }
	t.Cleanup(func() { lookPath = origLookPath })

	runner := &fakeCmdRunner{
		runFn: func(_ context.Context, _ string, _ []string, _ []string) ([]byte, error) {
			return []byte(`[{"optional":{"Issuer":"https://accounts.google.com","Subject":"user@example.com"}}]`), nil
		},
	}

	v := NewCosignVerifier(withVerifyRunner(runner))
	ref := "registry.io/image@sha256:abc123"

	// Offline keyless without bundle: should NOT set rekor log index.
	result, err := v.Verify(context.Background(), ref, VerifyOptions{
		Offline:              true,
		CertIdentity:         "user@example.com",
		CertIssuer:           "https://accounts.google.com",
		CertificateChainPath: "/tmp/chain.pem",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RekorLogIndex != -1 {
		t.Errorf("expected rekor log index -1 for offline keyless without bundle, got %d", result.RekorLogIndex)
	}

	// Offline keyless WITH bundle: should set rekor log index.
	result2, err := v.Verify(context.Background(), ref, VerifyOptions{
		Offline:      true,
		CertIdentity: "user@example.com",
		CertIssuer:   "https://accounts.google.com",
		BundlePath:   "/tmp/artifact.sigstore.json",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result2.RekorLogIndex != 0 {
		t.Errorf("expected rekor log index 0 for offline keyless with bundle, got %d", result2.RekorLogIndex)
	}
}

func TestNewMockVerifierOffline(t *testing.T) {
	v := NewMockVerifierOffline()
	ref := "registry.io/image@sha256:abc123"

	result, err := v.Verify(context.Background(), ref, VerifyOptions{
		Offline: true,
		KeyPath: "/tmp/cosign.pub",
	})
	if err != nil {
		t.Fatalf("mock offline verifier should succeed: %v", err)
	}
	if !result.Verified {
		t.Error("expected verified=true")
	}
	if !result.Offline {
		t.Error("expected offline=true in result")
	}
}

func TestMockVerifierOfflineWithBundle(t *testing.T) {
	v := NewMockVerifier()
	ref := "registry.io/image@sha256:abc123"

	result, err := v.Verify(context.Background(), ref, VerifyOptions{
		Offline:    true,
		KeyPath:    "/tmp/cosign.pub",
		BundlePath: "/tmp/artifact.sigstore.json",
	})
	if err != nil {
		t.Fatalf("mock verifier should succeed: %v", err)
	}
	if !result.BundleVerified {
		t.Error("expected bundleVerified=true when bundle provided")
	}
	if !result.Offline {
		t.Error("expected offline=true when offline option set")
	}
}

func TestMockVerifierOfflineKeylessNoRekor(t *testing.T) {
	v := NewMockVerifier()
	ref := "registry.io/image@sha256:abc123"

	result, err := v.Verify(context.Background(), ref, VerifyOptions{
		Offline:              true,
		CertIdentity:         "user@example.com",
		CertIssuer:           "https://accounts.google.com",
		CertificateChainPath: "/tmp/chain.pem",
	})
	if err != nil {
		t.Fatalf("mock verifier should succeed: %v", err)
	}
	if result.RekorLogIndex >= 0 {
		t.Errorf("expected rekor log index < 0 for offline keyless without bundle, got %d", result.RekorLogIndex)
	}
}
