package signing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ProvenanceVerifier checks SLSA provenance attestations on OCI artifacts.
type ProvenanceVerifier interface {
	// VerifyProvenance fetches and verifies the SLSA provenance attestation
	// for an OCI artifact. It returns a ProvenanceVerifyResult on success.
	VerifyProvenance(ctx context.Context, ref string, opts ProvenanceVerifyOptions) (*ProvenanceVerifyResult, error)
}

// ProvenanceVerifyOptions configures provenance verification.
type ProvenanceVerifyOptions struct {
	// ExpectedWorkflow is the GitHub Actions workflow URI that must appear
	// in the provenance certificate identity.
	// Example: "https://github.com/Kubedoll-Heavy-Industries/agentcontainers/.github/workflows/docker.yml"
	ExpectedWorkflow string

	// ExpectedSourceRepo is the source repository that must appear in the
	// provenance materials or invocation config source.
	// Example: "github.com/Kubedoll-Heavy-Industries/agentcontainers"
	ExpectedSourceRepo string

	// MinSLSALevel is the minimum acceptable SLSA build level (1-4).
	// Default is 1 (scripted build).
	MinSLSALevel SLSALevel

	// CertIssuer is the expected OIDC issuer (e.g. "https://token.actions.githubusercontent.com").
	CertIssuer string
}

// ProvenanceVerifyResult contains the outcome of a provenance verification.
type ProvenanceVerifyResult struct {
	// Verified is true if provenance was found and verified.
	Verified bool

	// SLSALevel is the determined SLSA build level.
	SLSALevel SLSALevel

	// BuilderID is the identity of the builder that produced the artifact.
	BuilderID string

	// SourceRepo is the source repository from which the artifact was built.
	SourceRepo string

	// SourceCommit is the git commit SHA from which the artifact was built.
	SourceCommit string

	// BuildTimestamp is when the build completed, if available.
	BuildTimestamp *time.Time

	// Provenance is the parsed provenance attestation.
	Provenance *Provenance
}

// SLSALevelString returns a human-readable string for a SLSA level.
func SLSALevelString(level SLSALevel) string {
	switch level {
	case SLSALevel0:
		return "SLSA L0 (none)"
	case SLSALevel1:
		return "SLSA L1 (scripted build)"
	case SLSALevel2:
		return "SLSA L2 (hosted build)"
	case SLSALevel3:
		return "SLSA L3 (hardened build)"
	case SLSALevel4:
		return "SLSA L4 (hermetic build)"
	default:
		return fmt.Sprintf("SLSA L%d (unknown)", level)
	}
}

// InTotoStatement represents an in-toto v1 attestation statement,
// which is the envelope format used by SLSA provenance attestations.
type InTotoStatement struct {
	Type          string          `json:"_type"`
	PredicateType string          `json:"predicateType"`
	Subject       []InTotoSubject `json:"subject"`
	Predicate     json.RawMessage `json:"predicate"`
}

// InTotoSubject identifies a build artifact subject in an attestation.
type InTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// ParseInTotoStatement parses an in-toto attestation statement and extracts
// the SLSA provenance predicate.
func ParseInTotoStatement(data []byte) (*InTotoStatement, *Provenance, error) {
	if len(data) == 0 {
		return nil, nil, errors.New("provenance: empty attestation data")
	}

	var stmt InTotoStatement
	if err := json.Unmarshal(data, &stmt); err != nil {
		return nil, nil, fmt.Errorf("provenance: invalid in-toto statement: %w", err)
	}

	if stmt.Type == "" {
		return nil, nil, errors.New("provenance: missing _type field in attestation")
	}

	// Parse the predicate as a SLSA provenance.
	prov, err := ParseProvenance(stmt.Predicate)
	if err != nil {
		return nil, nil, fmt.Errorf("provenance: invalid predicate: %w", err)
	}

	return &stmt, prov, nil
}

// ValidateProvenance checks that a provenance attestation meets the
// requirements specified in the options. It returns nil if all checks pass.
//
// NOTE: This validates predicate content only (builder ID, source repo, SLSA level).
// Cryptographic certificate binding (signer identity) is enforced separately by
// execVerifyAttestation via cosign's --certificate-identity-regexp flag.
func ValidateProvenance(prov *Provenance, opts ProvenanceVerifyOptions) error {
	if prov == nil {
		return errors.New("provenance: nil provenance")
	}

	var errs []error

	// Check SLSA level meets minimum.
	level := prov.DetermineSLSALevel()
	minLevel := opts.MinSLSALevel
	if minLevel == 0 {
		minLevel = SLSALevel1 // Default minimum.
	}
	if level < minLevel {
		errs = append(errs, fmt.Errorf("provenance: SLSA level %d is below minimum %d",
			level, minLevel))
	}

	// Check expected workflow in builder ID.
	if opts.ExpectedWorkflow != "" {
		if !strings.Contains(prov.Builder.ID, opts.ExpectedWorkflow) {
			errs = append(errs, fmt.Errorf(
				"provenance: builder ID %q does not match expected workflow %q",
				prov.Builder.ID, opts.ExpectedWorkflow))
		}
	}

	// Check expected source repository.
	if opts.ExpectedSourceRepo != "" {
		found := false

		// Check invocation config source URI.
		if strings.Contains(prov.Invocation.ConfigSource.URI, opts.ExpectedSourceRepo) {
			found = true
		}

		// Check materials.
		for _, m := range prov.Materials {
			if strings.Contains(m.URI, opts.ExpectedSourceRepo) {
				found = true
				break
			}
		}

		if !found {
			errs = append(errs, fmt.Errorf(
				"provenance: source repository %q not found in provenance materials or config source",
				opts.ExpectedSourceRepo))
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// ExtractSourceInfo extracts source repository and commit information from
// provenance data. Returns (repo, commit) strings.
func ExtractSourceInfo(prov *Provenance) (repo string, commit string) {
	if prov == nil {
		return "", ""
	}

	// Try invocation config source first.
	if prov.Invocation.ConfigSource.URI != "" {
		repo = prov.Invocation.ConfigSource.URI
		if sha, ok := prov.Invocation.ConfigSource.Digest["sha1"]; ok {
			commit = sha
		}
	}

	// Fall back to materials for the source repo.
	if repo == "" {
		for _, m := range prov.Materials {
			if strings.HasPrefix(m.URI, "git+") {
				repo = m.URI
				if sha, ok := m.Digest["sha1"]; ok {
					commit = sha
				}
				break
			}
		}
	}

	return repo, commit
}

// CosignProvenanceVerifier implements ProvenanceVerifier by shelling out
// to `cosign verify-attestation`.
type CosignProvenanceVerifier struct {
	verifyFunc func(ctx context.Context, ref string, opts ProvenanceVerifyOptions) (*ProvenanceVerifyResult, error)
	runner     cmdRunner
}

// CosignProvenanceVerifierOption configures a CosignProvenanceVerifier.
type CosignProvenanceVerifierOption func(*CosignProvenanceVerifier)

// WithProvenanceVerifyFunc injects a custom verify function for testing.
func WithProvenanceVerifyFunc(fn func(ctx context.Context, ref string, opts ProvenanceVerifyOptions) (*ProvenanceVerifyResult, error)) CosignProvenanceVerifierOption {
	return func(v *CosignProvenanceVerifier) {
		v.verifyFunc = fn
	}
}

// NewCosignProvenanceVerifier creates a new CosignProvenanceVerifier.
func NewCosignProvenanceVerifier(opts ...CosignProvenanceVerifierOption) *CosignProvenanceVerifier {
	v := &CosignProvenanceVerifier{
		runner: execRunner{},
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Compile-time check that CosignProvenanceVerifier satisfies ProvenanceVerifier.
var _ ProvenanceVerifier = (*CosignProvenanceVerifier)(nil)

// VerifyProvenance verifies the SLSA provenance attestation for the given OCI artifact.
func (v *CosignProvenanceVerifier) VerifyProvenance(ctx context.Context, ref string, opts ProvenanceVerifyOptions) (*ProvenanceVerifyResult, error) {
	if ref == "" {
		return nil, errors.New("provenance verify: empty artifact reference")
	}

	if v.verifyFunc != nil {
		return v.verifyFunc(ctx, ref, opts)
	}

	return v.execVerifyAttestation(ctx, ref, opts)
}

// buildVerifyAttestationArgs constructs the `cosign verify-attestation` arguments.
func buildVerifyAttestationArgs(ref string, opts ProvenanceVerifyOptions) []string {
	args := []string{"verify-attestation", "--type", "slsaprovenance1"}

	if opts.CertIssuer != "" {
		args = append(args, "--certificate-oidc-issuer", opts.CertIssuer)
	}

	if opts.ExpectedWorkflow != "" {
		args = append(args, "--certificate-identity-regexp", opts.ExpectedWorkflow)
	}

	args = append(args, ref)
	return args
}

// execVerifyAttestation runs `cosign verify-attestation` and parses the output.
func (v *CosignProvenanceVerifier) execVerifyAttestation(ctx context.Context, ref string, opts ProvenanceVerifyOptions) (*ProvenanceVerifyResult, error) {
	if _, err := lookPath("cosign"); err != nil {
		return nil, errors.New("provenance verify: cosign binary not found on PATH")
	}

	args := buildVerifyAttestationArgs(ref, opts)
	env := []string{"COSIGN_EXPERIMENTAL=1"}

	output, err := v.runner.Run(ctx, "cosign", args, env)
	if err != nil {
		return nil, fmt.Errorf("provenance verify: %w", err)
	}

	// cosign outputs one JSON object per attestation (NDJSON, one per line).
	// Parse the first non-empty line.
	lines := bytes.Split(bytes.TrimSpace(output), []byte("\n"))
	if len(lines) == 0 || len(lines[0]) == 0 {
		return nil, errors.New("provenance verify: empty output from cosign")
	}
	_, prov, err := ParseInTotoStatement(lines[0])
	if err != nil {
		return nil, fmt.Errorf("provenance verify: %w", err)
	}

	// Validate against options.
	if err := ValidateProvenance(prov, opts); err != nil {
		return nil, err
	}

	repo, commit := ExtractSourceInfo(prov)

	result := &ProvenanceVerifyResult{
		Verified:     true,
		SLSALevel:    prov.DetermineSLSALevel(),
		BuilderID:    prov.Builder.ID,
		SourceRepo:   repo,
		SourceCommit: commit,
		Provenance:   prov,
	}

	if prov.Metadata.BuildFinishedOn != nil {
		ts := *prov.Metadata.BuildFinishedOn
		result.BuildTimestamp = &ts
	}

	return result, nil
}

// NewMockProvenanceVerifier creates a ProvenanceVerifier that returns a
// successful verification with the given provenance data.
func NewMockProvenanceVerifier(prov *Provenance) ProvenanceVerifier {
	return NewCosignProvenanceVerifier(WithProvenanceVerifyFunc(
		func(_ context.Context, _ string, opts ProvenanceVerifyOptions) (*ProvenanceVerifyResult, error) {
			if prov == nil {
				return nil, errors.New("provenance verify: no provenance found")
			}

			if err := ValidateProvenance(prov, opts); err != nil {
				return nil, err
			}

			repo, commit := ExtractSourceInfo(prov)

			result := &ProvenanceVerifyResult{
				Verified:     true,
				SLSALevel:    prov.DetermineSLSALevel(),
				BuilderID:    prov.Builder.ID,
				SourceRepo:   repo,
				SourceCommit: commit,
				Provenance:   prov,
			}

			if prov.Metadata.BuildFinishedOn != nil {
				ts := *prov.Metadata.BuildFinishedOn
				result.BuildTimestamp = &ts
			}

			return result, nil
		},
	))
}

// NewMockProvenanceVerifierFailing creates a ProvenanceVerifier that always fails.
func NewMockProvenanceVerifierFailing(errMsg string) ProvenanceVerifier {
	return NewCosignProvenanceVerifier(WithProvenanceVerifyFunc(
		func(_ context.Context, ref string, _ ProvenanceVerifyOptions) (*ProvenanceVerifyResult, error) {
			if errMsg == "" {
				errMsg = "no provenance attestation found"
			}
			return nil, fmt.Errorf("provenance verify: %s: %s", ref, errMsg)
		},
	))
}
