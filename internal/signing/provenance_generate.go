package signing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Well-known in-toto and SLSA constants.
const (
	// InTotoStatementType is the in-toto v1 statement type.
	InTotoStatementType = "https://in-toto.io/Statement/v1"

	// SLSAProvenancePredicateType is the SLSA v1 provenance predicate type.
	SLSAProvenancePredicateType = "https://slsa.dev/provenance/v1"

	// GitHubActionsIssuer is the OIDC issuer for GitHub Actions.
	GitHubActionsIssuer = "https://token.actions.githubusercontent.com"

	// GitHubActionsBuildType is the build type for GitHub Actions workflows.
	GitHubActionsBuildType = "https://github.com/slsa-framework/slsa-github-generator/generic@v2"
)

// GitHubEnv holds the GitHub Actions environment variables used to construct
// SLSA provenance. Each field corresponds to a GITHUB_* env var.
type GitHubEnv struct {
	Actor      string // GITHUB_ACTOR
	Workflow   string // GITHUB_WORKFLOW
	SHA        string // GITHUB_SHA
	Ref        string // GITHUB_REF
	RunID      string // GITHUB_RUN_ID
	ServerURL  string // GITHUB_SERVER_URL
	Repository string // GITHUB_REPOSITORY
}

// ReadGitHubEnv reads GitHub Actions environment variables from the process
// environment. Returns an error if any required variable is missing.
func ReadGitHubEnv() (*GitHubEnv, error) {
	env := &GitHubEnv{
		Actor:      os.Getenv("GITHUB_ACTOR"),
		Workflow:   os.Getenv("GITHUB_WORKFLOW"),
		SHA:        os.Getenv("GITHUB_SHA"),
		Ref:        os.Getenv("GITHUB_REF"),
		RunID:      os.Getenv("GITHUB_RUN_ID"),
		ServerURL:  os.Getenv("GITHUB_SERVER_URL"),
		Repository: os.Getenv("GITHUB_REPOSITORY"),
	}

	var errs []error
	if env.SHA == "" {
		errs = append(errs, errors.New("GITHUB_SHA is required"))
	}
	if env.Repository == "" {
		errs = append(errs, errors.New("GITHUB_REPOSITORY is required"))
	}
	if env.Workflow == "" {
		errs = append(errs, errors.New("GITHUB_WORKFLOW is required"))
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("github env: %w", errors.Join(errs...))
	}

	// Default server URL to github.com if not set.
	if env.ServerURL == "" {
		env.ServerURL = "https://github.com"
	}

	return env, nil
}

// NewProvenanceFromGitHub creates a Provenance from GitHub Actions environment
// variables. The builder ID is constructed from the server URL, repository, and
// workflow name. Source material includes the repository URI and commit SHA.
func NewProvenanceFromGitHub(env *GitHubEnv) (*Provenance, error) {
	if env == nil {
		return nil, errors.New("provenance: nil GitHub environment")
	}

	// Build the builder ID: serverURL/repository/.github/workflows/workflow
	builderID := fmt.Sprintf("%s/%s/.github/workflows/%s",
		strings.TrimRight(env.ServerURL, "/"),
		env.Repository,
		env.Workflow,
	)

	p := NewProvenance(builderID)
	if p == nil {
		return nil, errors.New("provenance: failed to create provenance (empty builder ID)")
	}

	p.BuildType = GitHubActionsBuildType

	// Source repo URI follows git+URL@ref convention.
	sourceURI := fmt.Sprintf("git+%s/%s", strings.TrimRight(env.ServerURL, "/"), env.Repository)
	if env.Ref != "" {
		sourceURI += "@" + env.Ref
	}

	p.Invocation = ProvenanceInvocation{
		ConfigSource: ProvenanceConfigSource{
			URI:    sourceURI,
			Digest: map[string]string{"sha1": env.SHA},
		},
	}

	if env.RunID != "" {
		p.Invocation.Parameters = map[string]string{
			"runID": env.RunID,
		}
	}

	// Add source repo as a material.
	p.AddMaterial(sourceURI, map[string]string{"sha1": env.SHA})

	return p, nil
}

// GenerateInTotoStatement wraps a Provenance in an in-toto v1 attestation
// statement with the given subject (artifact name and digest).
func GenerateInTotoStatement(prov *Provenance, subjectName string, subjectDigest map[string]string) (*InTotoStatement, error) {
	if prov == nil {
		return nil, errors.New("provenance: nil provenance")
	}
	if subjectName == "" {
		return nil, errors.New("provenance: empty subject name")
	}
	if len(subjectDigest) == 0 {
		return nil, errors.New("provenance: empty subject digest")
	}

	predicate, err := json.Marshal(prov)
	if err != nil {
		return nil, fmt.Errorf("provenance: marshal predicate: %w", err)
	}

	stmt := &InTotoStatement{
		Type:          InTotoStatementType,
		PredicateType: SLSAProvenancePredicateType,
		Subject: []InTotoSubject{
			{
				Name:   subjectName,
				Digest: subjectDigest,
			},
		},
		Predicate: predicate,
	}

	return stmt, nil
}

// Attester signs and attaches SLSA provenance attestations to OCI artifacts.
type Attester interface {
	// Attest creates and attaches a SLSA provenance attestation to the OCI
	// artifact at ref. The provenance data is wrapped in an in-toto statement
	// and signed using cosign attest.
	Attest(ctx context.Context, ref string, stmt *InTotoStatement, opts AttestOptions) (*AttestResult, error)
}

// AttestOptions configures how an attestation is created and attached.
type AttestOptions struct {
	// KeyPath is the path to a private key for key-based signing.
	// If empty, keyless (Fulcio + Rekor) signing is used.
	KeyPath string

	// RekorURL is the Rekor transparency log URL.
	RekorURL string
}

// AttestResult contains the outcome of an attestation operation.
type AttestResult struct {
	// Ref is the artifact reference that was attested.
	Ref string

	// AttestationDigest is the digest of the attestation artifact in the registry.
	AttestationDigest string

	// RekorLogIndex is the Rekor transparency log entry index, if applicable.
	// -1 indicates no Rekor entry was created.
	RekorLogIndex int64

	// Timestamp is when the attestation was created.
	Timestamp time.Time
}

// CosignAttester implements Attester by executing `cosign attest`.
type CosignAttester struct {
	attestFunc func(ctx context.Context, ref string, stmt *InTotoStatement, opts AttestOptions) (*AttestResult, error)
	runner     cmdRunner
}

// CosignAttesterOption configures a CosignAttester.
type CosignAttesterOption func(*CosignAttester)

// WithAttestFunc injects a custom attest function for testing.
func WithAttestFunc(fn func(ctx context.Context, ref string, stmt *InTotoStatement, opts AttestOptions) (*AttestResult, error)) CosignAttesterOption {
	return func(a *CosignAttester) {
		a.attestFunc = fn
	}
}

// NewCosignAttester creates a new CosignAttester.
func NewCosignAttester(opts ...CosignAttesterOption) *CosignAttester {
	a := &CosignAttester{
		runner: execRunner{},
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Compile-time check that CosignAttester satisfies the Attester interface.
var _ Attester = (*CosignAttester)(nil)

// Attest creates and attaches a SLSA provenance attestation.
func (a *CosignAttester) Attest(ctx context.Context, ref string, stmt *InTotoStatement, opts AttestOptions) (*AttestResult, error) {
	if ref == "" {
		return nil, errors.New("attest: empty artifact reference")
	}
	if stmt == nil {
		return nil, errors.New("attest: nil in-toto statement")
	}

	if a.attestFunc != nil {
		return a.attestFunc(ctx, ref, stmt, opts)
	}

	return a.execAttest(ctx, ref, stmt, opts)
}

// execAttest runs `cosign attest` with the SLSA provenance predicate.
// cosign constructs the full in-toto statement envelope itself when given
// --type slsaprovenance; we only pass the predicate body via --predicate.
func (a *CosignAttester) execAttest(ctx context.Context, ref string, stmt *InTotoStatement, opts AttestOptions) (*AttestResult, error) {
	if _, err := lookPath("cosign"); err != nil {
		return nil, errors.New("attest: cosign binary not found on PATH")
	}

	// Marshal only the predicate body — cosign wraps it in the statement envelope.
	stmtData, err := json.Marshal(stmt.Predicate)
	if err != nil {
		return nil, fmt.Errorf("attest: marshal predicate: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "provenance-*.json")
	if err != nil {
		return nil, fmt.Errorf("attest: create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name()) //nolint:errcheck // best-effort cleanup

	if _, err := tmpFile.Write(stmtData); err != nil {
		_ = tmpFile.Close()
		return nil, fmt.Errorf("attest: write predicate: %w", err)
	}
	_ = tmpFile.Close()

	args := buildAttestArgs(ref, tmpFile.Name(), opts)
	env := buildAttestEnv(opts)

	if _, err := a.runner.Run(ctx, "cosign", args, env); err != nil {
		return nil, fmt.Errorf("attest: %w", err)
	}

	result := &AttestResult{
		Ref:           ref,
		RekorLogIndex: -1,
		Timestamp:     time.Now().UTC(),
	}

	if opts.KeyPath == "" {
		result.RekorLogIndex = 0
	}

	return result, nil
}

// buildAttestArgs constructs the `cosign attest` command arguments.
func buildAttestArgs(ref, predicatePath string, opts AttestOptions) []string {
	args := []string{"attest", "--type", "slsaprovenance", "--predicate", predicatePath}

	if opts.KeyPath != "" {
		args = append(args, "--key", opts.KeyPath)
	}

	if opts.RekorURL != "" {
		args = append(args, "--rekor-url", opts.RekorURL)
	}

	args = append(args, "--yes")
	args = append(args, ref)
	return args
}

// buildAttestEnv constructs environment variables for `cosign attest`.
func buildAttestEnv(opts AttestOptions) []string {
	var env []string
	if opts.KeyPath == "" {
		env = append(env, "COSIGN_EXPERIMENTAL=1")
	}
	return env
}

// ValidateBuilderIdentity checks that the provenance builder ID matches at
// least one of the trusted builders. Returns nil if the builder is trusted,
// or an error describing the mismatch.
func ValidateBuilderIdentity(prov *Provenance, trustedBuilders []string) error {
	if prov == nil {
		return errors.New("provenance: nil provenance")
	}
	if len(trustedBuilders) == 0 {
		// No trusted builders configured; skip validation.
		return nil
	}

	for _, trusted := range trustedBuilders {
		if strings.Contains(prov.Builder.ID, trusted) {
			return nil
		}
	}

	return fmt.Errorf("provenance: builder %q is not in trusted builders list", prov.Builder.ID)
}

// NewMockAttester creates an Attester that succeeds for any valid input.
func NewMockAttester() Attester {
	return NewCosignAttester(WithAttestFunc(
		func(_ context.Context, ref string, _ *InTotoStatement, _ AttestOptions) (*AttestResult, error) {
			return &AttestResult{
				Ref:               ref,
				AttestationDigest: "sha256:mock-attestation-digest",
				RekorLogIndex:     12345,
				Timestamp:         time.Now().UTC(),
			}, nil
		},
	))
}

// NewMockAttesterFailing creates an Attester that always fails.
func NewMockAttesterFailing(errMsg string) Attester {
	return NewCosignAttester(WithAttestFunc(
		func(_ context.Context, ref string, _ *InTotoStatement, _ AttestOptions) (*AttestResult, error) {
			if errMsg == "" {
				errMsg = "attestation failed"
			}
			return nil, fmt.Errorf("attest: %s: %s", ref, errMsg)
		},
	))
}
