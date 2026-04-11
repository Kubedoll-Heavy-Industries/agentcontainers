package signing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrVerifyNotConfigured is returned when cosign is not found on PATH.
var ErrVerifyNotConfigured = errors.New("sigstore verification not configured: cosign binary not found on PATH")

// Verifier verifies OCI artifact signatures.
type Verifier interface {
	// Verify checks that the OCI artifact at ref has a valid signature.
	Verify(ctx context.Context, ref string, opts VerifyOptions) (*VerifyResult, error)
}

// VerifyOptions configures signature verification.
type VerifyOptions struct {
	// KeyPath is the path to a public key for key-based verification.
	// If empty, keyless verification is used.
	KeyPath string

	// CertIdentity is the expected certificate identity for keyless verification
	// (e.g. "user@example.com" or a workflow URI).
	CertIdentity string

	// CertIssuer is the expected OIDC issuer for keyless verification
	// (e.g. "https://accounts.google.com").
	CertIssuer string

	// RekorURL is the Rekor transparency log URL. Defaults to the public
	// Rekor instance if empty.
	RekorURL string

	// Offline enables offline verification mode. When true, verification
	// does not contact Rekor or Fulcio. Requires either a Sigstore bundle
	// (BundlePath) or a trusted TUF root (TrustedRootPath) with a key.
	Offline bool

	// TrustedRootPath is the path to a Sigstore TUF trusted root JSON file
	// for offline verification. Used when Offline is true and keyless
	// verification needs to validate certificate chains without Fulcio.
	TrustedRootPath string

	// BundlePath is the path to a Sigstore bundle file (.sigstore.json)
	// containing the signature, certificate, and Rekor inclusion proof.
	// When provided, verification uses the bundled proof instead of
	// querying the live Rekor transparency log.
	BundlePath string

	// CertificateChainPath is the path to a PEM file containing the
	// certificate chain for offline certificate verification. Used when
	// Offline is true and a custom CA chain is needed.
	CertificateChainPath string
}

// VerifyResult contains the outcome of a signature verification.
type VerifyResult struct {
	// Verified is true if a valid signature was found.
	Verified bool

	// SignerIdentity is the identity of the signer (email, URI, etc.).
	SignerIdentity string

	// IssuerURL is the OIDC issuer that issued the signing certificate.
	IssuerURL string

	// RekorLogIndex is the Rekor transparency log entry index, if applicable.
	// -1 indicates no Rekor entry was checked.
	RekorLogIndex int64

	// Certificate is the PEM-encoded signing certificate, if available.
	Certificate string

	// Timestamp is when the signature was created.
	Timestamp time.Time

	// BundleVerified is true when the signature was verified using a
	// Sigstore bundle (offline or bundle mode).
	BundleVerified bool

	// Offline is true when the verification was performed in offline mode.
	Offline bool
}

// CosignVerifier implements Verifier by executing the cosign CLI binary.
type CosignVerifier struct {
	verifyFunc func(ctx context.Context, ref string, opts VerifyOptions) (*VerifyResult, error)
	runner     cmdRunner
}

// CosignVerifierOption configures a CosignVerifier.
type CosignVerifierOption func(*CosignVerifier)

// WithVerifyFunc injects a custom verify function, used for testing.
func WithVerifyFunc(fn func(ctx context.Context, ref string, opts VerifyOptions) (*VerifyResult, error)) CosignVerifierOption {
	return func(v *CosignVerifier) {
		v.verifyFunc = fn
	}
}

// withVerifyRunner injects a custom command runner (for testing).
func withVerifyRunner(r cmdRunner) CosignVerifierOption {
	return func(v *CosignVerifier) {
		v.runner = r
	}
}

// NewCosignVerifier creates a new CosignVerifier.
func NewCosignVerifier(opts ...CosignVerifierOption) *CosignVerifier {
	v := &CosignVerifier{
		runner: execRunner{},
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Compile-time check that CosignVerifier satisfies the Verifier interface.
var _ Verifier = (*CosignVerifier)(nil)

// Verify checks the OCI artifact signature at ref.
func (v *CosignVerifier) Verify(ctx context.Context, ref string, opts VerifyOptions) (*VerifyResult, error) {
	if err := validateVerifyRef(ref); err != nil {
		return nil, fmt.Errorf("cosign verify: %w", err)
	}

	if err := validateVerifyOptions(opts); err != nil {
		return nil, fmt.Errorf("cosign verify: %w", err)
	}

	if v.verifyFunc != nil {
		return v.verifyFunc(ctx, ref, opts)
	}

	return v.execVerify(ctx, ref, opts)
}

// buildVerifyArgs constructs the cosign verify command arguments.
func buildVerifyArgs(ref string, opts VerifyOptions) []string {
	args := []string{"verify"}

	if opts.KeyPath != "" {
		args = append(args, "--key", opts.KeyPath)
	}

	if opts.CertIdentity != "" {
		args = append(args, "--certificate-identity", opts.CertIdentity)
	}

	if opts.CertIssuer != "" {
		args = append(args, "--certificate-oidc-issuer", opts.CertIssuer)
	}

	if opts.RekorURL != "" {
		args = append(args, "--rekor-url", opts.RekorURL)
	}

	// Offline verification flags.
	if opts.Offline {
		args = append(args, "--offline-verification")

		// When offline without a bundle, disable tlog verification
		// since there is no Rekor proof available.
		if opts.BundlePath == "" {
			args = append(args, "--insecure-ignore-tlog=true")
		}
	}

	if opts.BundlePath != "" {
		args = append(args, "--bundle", opts.BundlePath)
	}

	if opts.TrustedRootPath != "" {
		args = append(args, "--trusted-root", opts.TrustedRootPath)
	}

	if opts.CertificateChainPath != "" {
		args = append(args, "--certificate-chain", opts.CertificateChainPath)
	}

	args = append(args, ref)
	return args
}

// buildVerifyEnv constructs environment variables for cosign verify.
func buildVerifyEnv(opts VerifyOptions) []string {
	var env []string

	// For keyless verification without explicit cert options, enable experimental.
	// Skip this in offline mode since we do not contact Fulcio/Rekor.
	if opts.KeyPath == "" && opts.CertIdentity == "" && !opts.Offline {
		env = append(env, "COSIGN_EXPERIMENTAL=1")
	}

	// For offline mode with a trusted root, set the TUF root environment variable
	// so cosign uses the local TUF root instead of fetching from the network.
	if opts.Offline && opts.TrustedRootPath != "" {
		env = append(env, "TUF_ROOT="+opts.TrustedRootPath)
	}

	return env
}

// cosignVerifyEntry is the shape of one element in cosign verify's JSON output.
// cosign prints a JSON array of these to stdout when verification succeeds.
type cosignVerifyEntry struct {
	Optional struct {
		Bundle *struct {
			Payload struct {
				LogIndex int64 `json:"logIndex"`
			} `json:"Payload"`
		} `json:"Bundle"`
		Issuer  string `json:"Issuer"`
		Subject string `json:"Subject"`
	} `json:"optional"`
}

// execVerify runs the cosign verify binary and parses its JSON output.
// cosign exits 0 and prints a non-empty JSON array when at least one signature
// is verified. A zero-length array or a missing array means no signatures were
// found, which we treat as a verification failure.
func (v *CosignVerifier) execVerify(ctx context.Context, ref string, opts VerifyOptions) (*VerifyResult, error) {
	if _, err := lookPath("cosign"); err != nil {
		return nil, ErrVerifyNotConfigured
	}

	args := buildVerifyArgs(ref, opts)
	env := buildVerifyEnv(opts)

	out, err := v.runner.Run(ctx, "cosign", args, env)
	if err != nil {
		return nil, fmt.Errorf("cosign verify: %w", err)
	}

	// cosign prints a JSON array of verified signatures to stdout.
	// Parse it to confirm at least one signature was actually verified and
	// to extract signer identity / Rekor log index from the real output.
	var entries []cosignVerifyEntry
	if len(out) > 0 {
		// cosign may prepend non-JSON status lines; find the first '['.
		idx := strings.IndexByte(string(out), '[')
		if idx >= 0 {
			_ = json.Unmarshal(out[idx:], &entries)
		}
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("cosign verify: no valid signatures found for %s", ref)
	}

	result := &VerifyResult{
		Verified:      true,
		RekorLogIndex: -1,
		Timestamp:     time.Now().UTC(),
		Offline:       opts.Offline,
	}

	if opts.BundlePath != "" {
		result.BundleVerified = true
	}

	// Populate identity fields from the first verified entry when available.
	first := entries[0]
	if first.Optional.Subject != "" {
		result.SignerIdentity = first.Optional.Subject
	} else if opts.KeyPath != "" {
		result.SignerIdentity = "key:" + opts.KeyPath
	} else if opts.CertIdentity != "" {
		result.SignerIdentity = opts.CertIdentity
	}

	if first.Optional.Issuer != "" {
		result.IssuerURL = first.Optional.Issuer
	} else if opts.CertIssuer != "" {
		result.IssuerURL = opts.CertIssuer
	}

	if first.Optional.Bundle != nil {
		result.RekorLogIndex = first.Optional.Bundle.Payload.LogIndex
	} else if !opts.Offline || opts.BundlePath != "" {
		// Online mode or bundle mode: Rekor was checked but index not available
		// from CLI output; use 0 as a sentinel for "checked but index unknown".
		result.RekorLogIndex = 0
	}

	return result, nil
}

// validateVerifyRef checks that an OCI reference is suitable for verification.
func validateVerifyRef(ref string) error {
	if ref == "" {
		return errors.New("empty artifact reference")
	}
	// For verification, we accept both tagged and digest references.
	// A digest reference is preferred but not required.
	return nil
}

// validateVerifyOptions checks that verification options are consistent.
func validateVerifyOptions(opts VerifyOptions) error {
	if opts.KeyPath != "" && opts.CertIdentity != "" {
		return errors.New("key-based and keyless verification are mutually exclusive")
	}
	if opts.CertIdentity != "" && opts.CertIssuer == "" {
		return errors.New("keyless verification requires both cert-identity and cert-issuer")
	}
	if opts.CertIssuer != "" && opts.CertIdentity == "" {
		return errors.New("keyless verification requires both cert-identity and cert-issuer")
	}

	// Offline-specific validation.
	if opts.Offline {
		// Offline mode requires some form of trust anchor: a key, a bundle,
		// a trusted root, or a certificate chain.
		hasAnchor := opts.KeyPath != "" || opts.BundlePath != "" ||
			opts.TrustedRootPath != "" || opts.CertificateChainPath != ""
		if !hasAnchor {
			return errors.New("offline verification requires --key, --bundle, --trusted-root, or --certificate-chain")
		}
	}

	// Bundle path can be used with or without offline mode,
	// but trusted-root and certificate-chain are only meaningful offline.
	if !opts.Offline && opts.TrustedRootPath != "" {
		return errors.New("--trusted-root requires --offline mode")
	}
	if !opts.Offline && opts.CertificateChainPath != "" {
		return errors.New("--certificate-chain requires --offline mode")
	}

	return nil
}

// NewMockVerifier creates a Verifier that succeeds for any valid input.
func NewMockVerifier() Verifier {
	return NewCosignVerifier(WithVerifyFunc(func(_ context.Context, ref string, opts VerifyOptions) (*VerifyResult, error) {
		return mockVerifyResult(ref, opts), nil
	}))
}

// NewMockVerifierFailing creates a Verifier that always reports verification failure.
func NewMockVerifierFailing() Verifier {
	return NewCosignVerifier(WithVerifyFunc(func(_ context.Context, ref string, _ VerifyOptions) (*VerifyResult, error) {
		return nil, fmt.Errorf("no valid signatures found for %s", ref)
	}))
}

// NewMockVerifierOffline creates a Verifier that simulates successful offline
// verification. It always returns verified=true with Offline=true.
func NewMockVerifierOffline() Verifier {
	return NewCosignVerifier(WithVerifyFunc(func(_ context.Context, ref string, opts VerifyOptions) (*VerifyResult, error) {
		// Force offline in the result regardless of what was passed.
		opts.Offline = true
		return mockVerifyResult(ref, opts), nil
	}))
}

func mockVerifyResult(ref string, opts VerifyOptions) *VerifyResult {
	result := &VerifyResult{
		Verified:      true,
		RekorLogIndex: -1,
		Timestamp:     time.Now().UTC(),
		Offline:       opts.Offline,
	}

	if opts.BundlePath != "" {
		result.BundleVerified = true
	}

	if opts.KeyPath != "" {
		result.SignerIdentity = "key:" + opts.KeyPath
	} else if opts.CertIdentity != "" {
		result.SignerIdentity = opts.CertIdentity
		result.IssuerURL = opts.CertIssuer
		if !opts.Offline || opts.BundlePath != "" {
			result.RekorLogIndex = 12345
		}
		result.Certificate = "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----"
	}

	_ = ref
	_ = strings.Contains(ref, "@") // ref used for context only

	return result
}
