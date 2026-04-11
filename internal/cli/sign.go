package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/signing"
)

func newSignCmd() *cobra.Command {
	var (
		keyPath        string
		keyless        bool
		certIdentity   string
		certIssuer     string
		rekorURL       string
		configPath     string
		lockfilePath   string
		allLocked      bool
		provenance     bool
		annotationStrs []string
	)

	cmd := &cobra.Command{
		Use:   "sign <oci-reference>",
		Short: "Sign an OCI artifact with Sigstore cosign",
		Long: `Sign an OCI artifact using Sigstore cosign. The artifact reference must
include a digest (e.g. registry.io/image@sha256:abc...).

Supports two signing modes:
  - Key-based: provide --key with a cosign private key path or KMS URI
  - Keyless (default): uses Fulcio CA + Rekor transparency log via OIDC

With --all, signs all OCI artifacts pinned in the lockfile instead of a
single reference.

With --provenance, generates a SLSA provenance attestation from GitHub Actions
environment variables and attaches it to the artifact using cosign attest.
This must be run in a GitHub Actions workflow where GITHUB_SHA, GITHUB_WORKFLOW,
and GITHUB_REPOSITORY are set.

Examples:
  ac sign registry.io/image@sha256:abc123...
  ac sign --key cosign.key registry.io/image@sha256:abc123...
  ac sign --keyless --cert-identity user@example.com --cert-issuer https://accounts.google.com registry.io/image@sha256:abc123...
  ac sign --provenance registry.io/image@sha256:abc123...
  ac sign --all --key cosign.key
  ac sign --all --annotation env=production`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if keyless && keyPath != "" {
				return fmt.Errorf("sign: --keyless and --key are mutually exclusive")
			}
			annotations := parseAnnotations(annotationStrs)
			if provenance && allLocked {
				return fmt.Errorf("sign: --provenance and --all are mutually exclusive")
			}
			if allLocked {
				if len(args) > 0 {
					return fmt.Errorf("sign: --all and explicit reference are mutually exclusive")
				}
				return runSignAll(cmd, configPath, lockfilePath, keyPath, certIdentity, certIssuer, rekorURL, annotations, nil)
			}
			if len(args) == 0 {
				return fmt.Errorf("sign: either provide an OCI reference or use --all")
			}
			if provenance {
				return runSignProvenance(cmd, args[0], keyPath, rekorURL, nil)
			}
			return runSign(cmd, args[0], keyPath, certIdentity, certIssuer, rekorURL, annotations, nil)
		},
	}

	cmd.Flags().StringVar(&keyPath, "key", "", "Path to cosign private key or KMS URI (omit for keyless)")
	cmd.Flags().BoolVar(&keyless, "keyless", false, "Use Fulcio keyless signing (default when --key is omitted)")
	cmd.Flags().StringVar(&certIdentity, "cert-identity", "", "Expected certificate identity for keyless signing")
	cmd.Flags().StringVar(&certIssuer, "cert-issuer", "", "Expected OIDC issuer for keyless signing")
	cmd.Flags().StringVar(&rekorURL, "rekor-url", "", "Rekor transparency log URL (default: public instance)")
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to agentcontainer.json (used with --all)")
	cmd.Flags().StringVarP(&lockfilePath, "lockfile", "l", "", "Path to agentcontainer-lock.json (used with --all)")
	cmd.Flags().BoolVar(&allLocked, "all", false, "Sign all OCI artifacts pinned in the lockfile")
	cmd.Flags().BoolVar(&provenance, "provenance", false, "Generate and attach SLSA provenance attestation (requires GitHub Actions env)")
	cmd.Flags().StringArrayVar(&annotationStrs, "annotation", nil, "Annotation key=value to attach to signature (repeatable)")

	return cmd
}

// parseAnnotations converts "key=value" strings into a map.
func parseAnnotations(strs []string) map[string]string {
	if len(strs) == 0 {
		return nil
	}
	m := make(map[string]string, len(strs))
	for _, s := range strs {
		k, v, ok := strings.Cut(s, "=")
		if ok {
			m[k] = v
		}
	}
	return m
}

// runSign signs a single OCI artifact reference.
func runSign(cmd *cobra.Command, ref, keyPath string, certIdentity, certIssuer, rekorURL string, annotations map[string]string, signer signing.Signer) error {
	out := cmd.OutOrStdout()
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	opts := signing.SignOptions{
		KeyPath:         keyPath,
		KeylessIssuer:   certIssuer,
		KeylessIdentity: certIdentity,
		RekorURL:        rekorURL,
		Annotations:     annotations,
	}

	if signer == nil {
		signer = signing.NewCosignSigner()
	}

	_, _ = fmt.Fprintf(out, "Signing %s...\n", ref)

	result, err := signer.Sign(ctx, ref, opts)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	_, _ = fmt.Fprintf(out, "Signed: %s\n", result.Ref)
	if result.SignatureDigest != "" {
		_, _ = fmt.Fprintf(out, "Signature digest: %s\n", result.SignatureDigest)
	}
	if result.RekorLogIndex >= 0 {
		_, _ = fmt.Fprintf(out, "Rekor log index: %d\n", result.RekorLogIndex)
	}
	if result.Certificate != "" {
		_, _ = fmt.Fprintln(out, "Fulcio certificate issued (keyless signing)")
	}

	return nil
}

// runSignAll signs all OCI artifacts pinned in the lockfile.
func runSignAll(cmd *cobra.Command, configPath, lockfilePath, keyPath string, certIdentity, certIssuer, rekorURL string, annotations map[string]string, signer signing.Signer) error {
	out := cmd.OutOrStdout()
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Resolve config and lockfile.
	var cfgDir string
	if configPath == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("sign: %w", err)
		}
		_, resolved, err := config.Load(cwd)
		if err != nil {
			return fmt.Errorf("sign: %w", err)
		}
		configPath = resolved
		cfgDir = filepath.Dir(resolved)
	} else {
		absPath, err := filepath.Abs(configPath)
		if err != nil {
			return fmt.Errorf("sign: resolving config path: %w", err)
		}
		configPath = absPath
		cfgDir = filepath.Dir(absPath)
	}

	cfg, err := config.ParseFile(configPath)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("sign: invalid config: %w", err)
	}

	if lockfilePath == "" {
		lockfilePath = filepath.Join(cfgDir, config.LockfileName)
	}

	lf, err := config.ParseLockfile(lockfilePath)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	if err := lf.Validate(); err != nil {
		return fmt.Errorf("sign: invalid lockfile: %w", err)
	}

	// Collect all artifact references with their pinned digests.
	refs := collectSignableRefs(cfg, lf)
	if len(refs) == 0 {
		_, _ = fmt.Fprintln(out, "No pinned OCI artifacts found in lockfile.")
		return nil
	}

	if signer == nil {
		signer = signing.NewCosignSigner()
	}

	opts := signing.SignOptions{
		KeyPath:         keyPath,
		KeylessIssuer:   certIssuer,
		KeylessIdentity: certIdentity,
		RekorURL:        rekorURL,
		Annotations:     annotations,
	}

	var signed, failed int
	for _, sr := range refs {
		_, _ = fmt.Fprintf(out, "Signing %s (%s)...\n", sr.label, sr.ref)

		result, err := signer.Sign(ctx, sr.ref, opts)
		if err != nil {
			_, _ = fmt.Fprintf(out, "  FAILED: %v\n", err)
			failed++
			continue
		}

		signed++
		_, _ = fmt.Fprintf(out, "  Signed: %s\n", result.Ref)
		if result.RekorLogIndex >= 0 {
			_, _ = fmt.Fprintf(out, "  Rekor log index: %d\n", result.RekorLogIndex)
		}
	}

	_, _ = fmt.Fprintf(out, "\nSigned %d artifact(s)", signed)
	if failed > 0 {
		_, _ = fmt.Fprintf(out, ", %d failed", failed)
	}
	_, _ = fmt.Fprintln(out, ".")

	if failed > 0 {
		return fmt.Errorf("sign: %d artifact(s) failed to sign", failed)
	}
	return nil
}

// signableRef pairs a display label with a digest-pinned OCI reference.
type signableRef struct {
	label string
	ref   string
}

// runSignProvenance generates and attaches a SLSA provenance attestation.
func runSignProvenance(cmd *cobra.Command, ref, keyPath, rekorURL string, attester signing.Attester) error {
	out := cmd.OutOrStdout()
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Parse GitHub Actions environment.
	env, err := signing.ReadGitHubEnv()
	if err != nil {
		return fmt.Errorf("sign --provenance: %w", err)
	}

	// Generate provenance from environment.
	prov, err := signing.NewProvenanceFromGitHub(env)
	if err != nil {
		return fmt.Errorf("sign --provenance: %w", err)
	}

	// Extract artifact name and digest from the reference.
	subjectName, subjectDigest, err := parseRefForAttestation(ref)
	if err != nil {
		return fmt.Errorf("sign --provenance: %w", err)
	}

	// Generate in-toto statement.
	stmt, err := signing.GenerateInTotoStatement(prov, subjectName, subjectDigest)
	if err != nil {
		return fmt.Errorf("sign --provenance: %w", err)
	}

	if attester == nil {
		attester = signing.NewCosignAttester()
	}

	attestOpts := signing.AttestOptions{
		KeyPath:  keyPath,
		RekorURL: rekorURL,
	}

	_, _ = fmt.Fprintf(out, "Generating SLSA provenance for %s...\n", ref)
	_, _ = fmt.Fprintf(out, "  Builder:   %s\n", prov.Builder.ID)
	_, _ = fmt.Fprintf(out, "  Source:    %s\n", prov.Invocation.ConfigSource.URI)
	_, _ = fmt.Fprintf(out, "  Commit:    %s\n", prov.Invocation.ConfigSource.Digest["sha1"])
	_, _ = fmt.Fprintf(out, "  SLSA level: %s\n", signing.SLSALevelString(prov.DetermineSLSALevel()))

	result, err := attester.Attest(ctx, ref, stmt, attestOpts)
	if err != nil {
		return fmt.Errorf("sign --provenance: %w", err)
	}

	_, _ = fmt.Fprintf(out, "Provenance attestation attached to %s\n", result.Ref)
	if result.AttestationDigest != "" {
		_, _ = fmt.Fprintf(out, "Attestation digest: %s\n", result.AttestationDigest)
	}
	if result.RekorLogIndex >= 0 {
		_, _ = fmt.Fprintf(out, "Rekor log index: %d\n", result.RekorLogIndex)
	}

	return nil
}

// parseRefForAttestation splits an OCI reference into name and digest map.
func parseRefForAttestation(ref string) (string, map[string]string, error) {
	idx := strings.Index(ref, "@sha256:")
	if idx < 0 {
		return "", nil, fmt.Errorf("artifact reference must include a digest (e.g. registry.io/image@sha256:abc...)")
	}
	name := ref[:idx]
	digest := ref[idx+1:] // "sha256:abc..."
	return name, map[string]string{"sha256": strings.TrimPrefix(digest, "sha256:")}, nil
}

// collectSignableRefs gathers OCI references from the config+lockfile that can be signed.
func collectSignableRefs(cfg *config.AgentContainer, lf *config.Lockfile) []signableRef {
	var refs []signableRef

	// Image.
	if cfg.Image != "" && lf.Resolved.Image != nil {
		refs = append(refs, signableRef{
			label: "image " + cfg.Image,
			ref:   cfg.Image + "@" + lf.Resolved.Image.Digest,
		})
	}

	// Features.
	for ref := range cfg.Features {
		resolved, ok := lf.Resolved.Features[ref]
		if !ok {
			continue
		}
		refs = append(refs, signableRef{
			label: "feature " + ref,
			ref:   ref + "@" + resolved.Digest,
		})
	}

	if cfg.Agent == nil || cfg.Agent.Tools == nil {
		return refs
	}

	// MCP servers.
	for name, mcp := range cfg.Agent.Tools.MCP {
		resolved, ok := lf.Resolved.MCP[name]
		if !ok {
			continue
		}
		refs = append(refs, signableRef{
			label: "mcp " + name,
			ref:   mcp.Image + "@" + resolved.Digest,
		})
	}

	// Skills.
	for name, skill := range cfg.Agent.Tools.Skills {
		resolved, ok := lf.Resolved.Skills[name]
		if !ok {
			continue
		}
		refs = append(refs, signableRef{
			label: "skill " + name,
			ref:   skill.Artifact + "@" + resolved.Digest,
		})
	}

	return refs
}
