package orgpolicy

import (
	"context"
	"errors"
	"fmt"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/oci"
)

// ExtractPolicy extracts the OrgPolicy from an OCI image manifest.
// It scans manifest layers for mediaType
// application/vnd.agentcontainers.orgpolicy.v1+json and takes the FIRST
// matching layer (org-controlled base policy — see F-3 fix).
//
// Only oci.ErrNoPolicyLayer (no policy layer in the manifest) returns a nil
// error with DefaultPolicy(). All other fetch errors — network failures, auth
// failures, digest mismatches, malformed manifests — are propagated as hard
// failures so that agentcontainer run exits rather than proceeding permissively.
func ExtractPolicy(ctx context.Context, imageRef string, opts ...oci.ResolverOption) (*OrgPolicy, error) {
	if imageRef == "" {
		return DefaultPolicy(), nil
	}

	resolver := oci.NewResolver(opts...)

	data, err := resolver.FetchPolicy(ctx, imageRef)
	if err != nil {
		// Only swallow the sentinel that means "this image has no policy layer".
		// Every other error (network, auth, MITM, digest mismatch, etc.) must
		// propagate so the caller fails closed rather than running permissively.
		if errors.Is(err, oci.ErrNoPolicyLayer) {
			return DefaultPolicy(), nil
		}
		return nil, fmt.Errorf("extract policy from %s: %w", imageRef, err)
	}

	p, err := parsePolicy(data)
	if err != nil {
		return nil, fmt.Errorf("extract policy from %s: %w", imageRef, err)
	}

	return p, nil
}
