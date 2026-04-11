package signing

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNotConfigured is returned when cosign is not found on PATH.
var ErrNotConfigured = errors.New("sigstore signing not configured: cosign binary not found on PATH")

// CosignSigner implements Signer by executing the cosign CLI binary.
type CosignSigner struct {
	// signFunc is an internal hook for testing. When non-nil, it replaces
	// the real exec-based implementation.
	signFunc func(ctx context.Context, ref string, opts SignOptions) (*SignResult, error)

	// runner executes shell commands. Defaults to execRunner{}.
	runner cmdRunner
}

// CosignOption configures a CosignSigner.
type CosignOption func(*CosignSigner)

// WithSignFunc injects a custom sign function, used for testing.
func WithSignFunc(fn func(ctx context.Context, ref string, opts SignOptions) (*SignResult, error)) CosignOption {
	return func(s *CosignSigner) {
		s.signFunc = fn
	}
}

// withRunner injects a custom command runner (for testing).
func withRunner(r cmdRunner) CosignOption {
	return func(s *CosignSigner) {
		s.runner = r
	}
}

// NewCosignSigner creates a new CosignSigner.
func NewCosignSigner(opts ...CosignOption) *CosignSigner {
	s := &CosignSigner{
		runner: execRunner{},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Compile-time check that CosignSigner satisfies the Signer interface.
var _ Signer = (*CosignSigner)(nil)

// Sign signs the OCI artifact at ref. It validates the reference format and
// signing options, then executes `cosign sign` with the appropriate flags.
func (s *CosignSigner) Sign(ctx context.Context, ref string, opts SignOptions) (*SignResult, error) {
	if err := validateRef(ref); err != nil {
		return nil, fmt.Errorf("cosign: %w", err)
	}

	if err := validateSignOptions(opts); err != nil {
		return nil, fmt.Errorf("cosign: %w", err)
	}

	if s.signFunc != nil {
		return s.signFunc(ctx, ref, opts)
	}

	return s.execSign(ctx, ref, opts)
}

// buildSignArgs constructs the cosign sign command arguments.
func buildSignArgs(ref string, opts SignOptions) []string {
	args := []string{"sign"}

	if opts.KeyPath != "" {
		args = append(args, "--key", opts.KeyPath)
	}

	if opts.RekorURL != "" {
		args = append(args, "--rekor-url", opts.RekorURL)
	}

	for k, v := range opts.Annotations {
		args = append(args, "--annotation", k+"="+v)
	}

	// Accept yes for prompts (e.g. pushing signature to registry).
	args = append(args, "--yes")

	args = append(args, ref)
	return args
}

// buildSignEnv constructs environment variables for cosign sign.
func buildSignEnv(opts SignOptions) []string {
	var env []string

	// For keyless signing (no key), enable experimental/keyless mode.
	if opts.KeyPath == "" {
		env = append(env, "COSIGN_EXPERIMENTAL=1")
	}

	if opts.RegistryAuth != "" {
		env = append(env, "COSIGN_DOCKER_MEDIA_TYPES=1")
	}

	return env
}

// execSign runs the cosign sign binary and parses the result.
func (s *CosignSigner) execSign(ctx context.Context, ref string, opts SignOptions) (*SignResult, error) {
	if _, err := lookPath("cosign"); err != nil {
		return nil, ErrNotConfigured
	}

	args := buildSignArgs(ref, opts)
	env := buildSignEnv(opts)

	if _, err := s.runner.Run(ctx, "cosign", args, env); err != nil {
		return nil, fmt.Errorf("cosign sign: %w", err)
	}

	// Extract digest from the ref.
	digest := ""
	if idx := strings.Index(ref, "@"); idx >= 0 {
		digest = ref[idx+1:]
	}

	result := &SignResult{
		Ref:           ref,
		Digest:        digest,
		RekorLogIndex: -1,
		SignedAt:      time.Now().UTC(),
	}

	// Keyless signing goes through Rekor, so mark it.
	if opts.KeyPath == "" {
		result.RekorLogIndex = 0 // Actual index not available from CLI output.
	}

	return result, nil
}

// validateRef checks that an OCI reference includes a digest.
func validateRef(ref string) error {
	if ref == "" {
		return errors.New("empty artifact reference")
	}
	if !strings.Contains(ref, "@sha256:") {
		return errors.New("artifact reference must include a digest (e.g. registry.io/image@sha256:abc...)")
	}
	return nil
}

// validateSignOptions checks that signing options are consistent.
func validateSignOptions(opts SignOptions) error {
	if opts.KeyPath != "" && opts.KeylessIssuer != "" {
		return errors.New("key-based and keyless signing are mutually exclusive")
	}
	if opts.KeylessIssuer != "" && opts.KeylessIdentity == "" {
		return errors.New("keyless signing requires both issuer and identity")
	}
	if opts.KeylessIdentity != "" && opts.KeylessIssuer == "" {
		return errors.New("keyless signing requires both issuer and identity")
	}
	return nil
}

// mockSignResult creates a SignResult for testing purposes.
func mockSignResult(ref string, opts SignOptions) *SignResult {
	// Extract digest from ref.
	digest := ""
	if idx := strings.Index(ref, "@"); idx >= 0 {
		digest = ref[idx+1:]
	}

	result := &SignResult{
		Ref:             ref,
		Digest:          digest,
		SignatureDigest: "sha256:sig-" + digest,
		RekorLogIndex:   -1,
		SignedAt:        time.Now().UTC(),
	}

	if opts.KeyPath == "" && opts.KeylessIssuer != "" {
		result.RekorLogIndex = 12345
		result.Certificate = "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----"
	}

	return result
}

// NewMockSigner creates a Signer that succeeds for any valid input.
// This is useful for testing the build command without real Sigstore infra.
func NewMockSigner() Signer {
	return NewCosignSigner(WithSignFunc(func(_ context.Context, ref string, opts SignOptions) (*SignResult, error) {
		return mockSignResult(ref, opts), nil
	}))
}
