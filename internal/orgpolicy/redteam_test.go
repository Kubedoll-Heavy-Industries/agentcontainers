// Red-team adversarial tests for the PRD-017 policy-as-OCI-layer implementation.
// Each test is named after the attack it demonstrates.
// Run with: go test -run TestRedTeam ./internal/orgpolicy/...
package orgpolicy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/oci"
)

// ----------------------------------------------------------------------------
// FINDING F-1 (CRITICAL): Policy bypass via any fetch error — FIXED
//
// ExtractPolicy() previously swallowed ALL errors from FetchPolicy(). After
// the fix it only swallows oci.ErrNoPolicyLayer. Network errors, HTTP 500s,
// and digest mismatches are propagated as hard failures (fail-closed).
// ----------------------------------------------------------------------------

func TestRedTeam_F1_FetchErrorYieldsPermissivePolicy(t *testing.T) {
	// Simulate a registry that returns 500 for every request.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`internal server error`))
	}))
	defer srv.Close()

	ref := srv.Listener.Addr().String() + "/myorg/agent-base:latest"
	_, err := ExtractPolicy(context.Background(), ref, oci.WithHTTPClient(srv.Client()))

	// FIXED: err must be non-nil so agentcontainer run fails closed.
	if err == nil {
		t.Errorf("REGRESSION F-1: ExtractPolicy returned nil error on registry 500 — " +
			"agentcontainer run will proceed without org policy enforcement.")
	}
}

func TestRedTeam_F1_NetworkTimeoutYieldsPermissivePolicy(t *testing.T) {
	// Simulate a server that accepts the connection but never responds
	// (the test just closes it immediately, simulating a reset).
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	srv.Close() // close before the request — connection refused

	ref := srv.Listener.Addr().String() + "/myorg/agent-base:latest"
	_, err := ExtractPolicy(context.Background(), ref, oci.WithHTTPClient(srv.Client()))

	// FIXED: connection refused must be a hard failure, not a permissive fallback.
	if err == nil {
		t.Errorf("REGRESSION F-1: ExtractPolicy returned nil error on connection refused — " +
			"attacker can block registry access to disable policy enforcement.")
	}
}

// ----------------------------------------------------------------------------
// FINDING F-2 (HIGH): No blob digest verification — FIXED
//
// fetchBlob now calls verifyDigest which computes sha256 of the returned bytes
// and compares to the descriptor digest. A MITM serving different content for
// a digest URL will be detected and the fetch will fail.
// ----------------------------------------------------------------------------

func TestRedTeam_F2_BlobDigestNotVerified(t *testing.T) {
	// The manifest says the policy blob has a specific digest.
	// The server returns different (permissive) bytes for that digest URL.
	restrictiveJSON := `{"requireSignatures": true, "minSLSALevel": 3}`
	restrictiveDigest := digestOf(restrictiveJSON) // real digest of restrictive policy
	permissiveJSON := `{}`                         // DefaultPolicy equivalent — no restrictions

	manifest := testManifest{
		Config: testDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []testDescriptor{
			{
				MediaType: "application/vnd.agentcontainers.orgpolicy.v1+json",
				Digest:    restrictiveDigest, // descriptor claims restrictive policy
				Size:      int64(len(restrictiveJSON)),
			},
		},
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/manifests/") {
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(manifest)
			return
		}
		if strings.Contains(r.URL.Path, "/blobs/") {
			// MITM: serve permissive policy instead of what the descriptor names.
			_, _ = w.Write([]byte(permissiveJSON))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ref := srv.Listener.Addr().String() + "/myorg/agent-base:latest"
	_, err := ExtractPolicy(context.Background(), ref, oci.WithHTTPClient(srv.Client()))

	// FIXED: digest mismatch must be detected and returned as a hard error.
	if err == nil {
		t.Errorf("REGRESSION F-2: blob digest not verified — MITM served permissive policy "+
			"for digest %q and ExtractPolicy accepted it without error. "+
			"Attacker can substitute any policy blob.", restrictiveDigest)
	}
	if err != nil && !strings.Contains(err.Error(), "digest mismatch") {
		t.Logf("F-2: got error (good) but not 'digest mismatch': %v", err)
	}
}

// ----------------------------------------------------------------------------
// FINDING F-3 (HIGH): Multiple policy layers — last-wins allows override — FIXED
//
// findPolicyLayer now returns the FIRST policy layer (first-wins). The org's
// base policy layer cannot be overridden by appending a derived permissive layer.
// ----------------------------------------------------------------------------

func TestRedTeam_F3_LastPolicyLayerWinsAllowsOverride(t *testing.T) {
	// Base image has a restrictive policy layer.
	// Attacker appends a permissive policy layer last.
	restrictivePolicy := `{"requireSignatures": true, "minSLSALevel": 3, "allowedCapabilities": ["filesystem"]}`
	permissivePolicy := `{}` // no restrictions

	restrictiveDigest := digestOf(restrictivePolicy)
	permissiveDigest := digestOf(permissivePolicy)

	manifest := testManifest{
		Config: testDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []testDescriptor{
			{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:" + strings.Repeat("f", 64), Size: 100},
			// Org's restrictive policy (appears FIRST):
			{MediaType: "application/vnd.agentcontainers.orgpolicy.v1+json", Digest: restrictiveDigest, Size: int64(len(restrictivePolicy))},
			{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:" + strings.Repeat("e", 64), Size: 200},
			// Attacker's permissive policy appended last:
			{MediaType: "application/vnd.agentcontainers.orgpolicy.v1+json", Digest: permissiveDigest, Size: int64(len(permissivePolicy))},
		},
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(manifest)
		case strings.Contains(r.URL.Path, "/blobs/"+restrictiveDigest):
			_, _ = w.Write([]byte(restrictivePolicy))
		case strings.Contains(r.URL.Path, "/blobs/"+permissiveDigest):
			_, _ = w.Write([]byte(permissivePolicy))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	ref := srv.Listener.Addr().String() + "/myorg/agent-base:latest"
	p, err := ExtractPolicy(context.Background(), ref, oci.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("ExtractPolicy() unexpected error: %v", err)
	}

	// FIXED: first-wins means the org's restrictive policy is returned, not the attacker's.
	if !p.RequireSignatures || p.MinSLSALevel == 0 || len(p.AllowedCapabilities) == 0 {
		t.Errorf("REGRESSION F-3: appending a permissive policy layer after the org's "+
			"restrictive policy overrides it. Got requireSignatures=%v minSLSALevel=%d allowedCaps=%v",
			p.RequireSignatures, p.MinSLSALevel, p.AllowedCapabilities)
	}
}

// ----------------------------------------------------------------------------
// FINDING F-4 (HIGH): cfg.Image is unverified — lockfile digest not used
//
// This is an architecture-level finding — fix is in run.go, not here.
// The test documents the vulnerability; fix is to pass the lockfile-pinned
// digest to ExtractPolicy: cfg.Image + "@" + lf.Resolved.Image.Digest.
// ----------------------------------------------------------------------------

func TestRedTeam_F4_MutableTagNotPinned_DocumentationTest(t *testing.T) {
	// Simulate a tag that initially resolves to a restrictive policy
	// but is silently updated to a permissive one between lock and run.
	currentPolicy := `{}` // permissive — what the tag now resolves to
	policyDigest := digestOf(currentPolicy)

	manifest := testManifest{
		Config: testDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []testDescriptor{
			{MediaType: "application/vnd.agentcontainers.orgpolicy.v1+json",
				Digest: policyDigest, Size: int64(len(currentPolicy))},
		},
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/manifests/latest"):
			// Tag "latest" now resolves to the permissive image.
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(manifest)
		case strings.Contains(r.URL.Path, "/blobs/"+policyDigest):
			_, _ = w.Write([]byte(currentPolicy))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	ref := srv.Listener.Addr().String() + "/myorg/agent-base:latest" // mutable tag
	p, err := ExtractPolicy(context.Background(), ref, oci.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("ExtractPolicy() error = %v", err)
	}

	// This succeeds — proving the tag is re-resolved at run time with no
	// cross-check against the lockfile's pinned digest.
	// Fix: runRun() must pass cfg.Image + "@" + lf.Resolved.Image.Digest.
	if !p.RequireSignatures && p.MinSLSALevel == 0 {
		t.Logf("VULNERABILITY F-4 (documented, fix in run.go): ExtractPolicy accepted mutable tag %q. "+
			"The lockfile-pinned digest is NOT used for policy extraction. "+
			"A tag mutation between 'ac lock' and 'ac run' bypasses policy.",
			ref)
		// NOTE: this test does NOT call t.Errorf because it demonstrates a design
		// flaw rather than a behavioral assertion — the behavior IS the vulnerability.
		// The fix is in run.go, not here.
	}
}

// ----------------------------------------------------------------------------
// FINDING F-5 (MEDIUM): MergePolicy only checks capability category presence,
// not capability content.
//
// extractCapabilityNames() returns capability category names (filesystem, network)
// based purely on whether the struct pointer is non-nil, not on what paths or
// hosts are declared.
//
// This is documented as a design gap. The fix adds AllowedFilesystemPaths and
// AllowedNetworkHosts to OrgPolicy and enforces them in MergePolicy.
// ----------------------------------------------------------------------------

func TestRedTeam_F5_CapabilityContentNotEnforced(t *testing.T) {
	// Org policy allows only "filesystem" capability but restricts to /data.
	// Workspace declares filesystem with unrestricted root access.
	org := &OrgPolicy{
		AllowedCapabilities:    []string{"filesystem"},
		AllowedFilesystemPaths: []string{"/data"},
	}
	ws := &config.AgentContainer{
		Image: "ghcr.io/myorg/base:latest",
		Agent: &config.AgentConfig{
			Capabilities: &config.Capabilities{
				Filesystem: &config.FilesystemCaps{
					Read:  []string{"/"}, // read entire filesystem — violates /data restriction
					Write: []string{"/"}, // write entire filesystem — violates /data restriction
				},
			},
		},
	}

	err := MergePolicy(org, ws)
	// FIXED: MergePolicy should now detect that "/" is not under any allowed path.
	if err == nil {
		t.Errorf("REGRESSION F-5: MergePolicy allowed filesystem capability with " +
			"read=['/'] write=['/'] when allowedFilesystemPaths=['/data']. " +
			"Org cannot restrict specific paths via AllowedFilesystemPaths.")
	}
}

func TestRedTeam_F5_AllowedPathsPermitsSubpaths(t *testing.T) {
	// A path that IS within the allowed paths should pass.
	org := &OrgPolicy{
		AllowedCapabilities:    []string{"filesystem"},
		AllowedFilesystemPaths: []string{"/data", "/workspace"},
	}
	ws := &config.AgentContainer{
		Image: "ghcr.io/myorg/base:latest",
		Agent: &config.AgentConfig{
			Capabilities: &config.Capabilities{
				Filesystem: &config.FilesystemCaps{
					Read:  []string{"/data/inputs"},
					Write: []string{"/workspace/output"},
				},
			},
		},
	}

	err := MergePolicy(org, ws)
	if err != nil {
		t.Errorf("MergePolicy() unexpected error for paths within allowedFilesystemPaths: %v", err)
	}
}

func TestRedTeam_F5_NetworkHostsEnforced(t *testing.T) {
	// Org restricts egress to api.example.com. Workspace tries to add github.com.
	org := &OrgPolicy{
		AllowedCapabilities: []string{"network"},
		AllowedNetworkHosts: []string{"api.example.com"},
	}
	ws := &config.AgentContainer{
		Image: "ghcr.io/myorg/base:latest",
		Agent: &config.AgentConfig{
			Capabilities: &config.Capabilities{
				Network: &config.NetworkCaps{
					Egress: []config.EgressRule{
						{Host: "api.example.com", Port: 443},
						{Host: "github.com", Port: 443}, // not in allowedNetworkHosts
					},
				},
			},
		},
	}

	err := MergePolicy(org, ws)
	if err == nil {
		t.Errorf("MergePolicy() should reject network egress to host not in allowedNetworkHosts")
	}
	if err != nil && !strings.Contains(err.Error(), "github.com") {
		t.Errorf("error should mention the disallowed host, got: %v", err)
	}
}

// ----------------------------------------------------------------------------
// FINDING F-6 (MEDIUM, design gap): Namespace prefix matching allows bare refs
//
// This is documented as expected behavior (not a regression). Fix: reject bare
// refs in ValidateAllowlistPatterns.
// ----------------------------------------------------------------------------

func TestRedTeam_F6_NamespacePrefixAllowsBareRef(t *testing.T) {
	// Org allows "ghcr.io/myorg/tools/" namespace.
	allowlist := []string{"ghcr.io/myorg/tools/"}

	// Bare ref (no tag, no digest) — resolves to :latest at pull time.
	bareRef := "ghcr.io/myorg/tools/evil"

	if !MatchesMCPAllowlist(bareRef, allowlist) {
		t.Skip("behavior already changed; skip")
	}

	t.Logf("FINDING F-6: bare ref %q matches namespace prefix allowlist %v. "+
		"This resolves to :latest at pull time, effectively bypassing tag pinning. "+
		"Fix: reject bare refs (no tag, no digest) in ValidateAllowlistPatterns "+
		"and/or in MatchesMCPAllowlist.", bareRef, allowlist)
	// Not t.Errorf because the current matching is as documented; this is a
	// design concern, not a bug. But it should be flagged for the org policy
	// author who believes they are pinning to specific versions.
}

// ----------------------------------------------------------------------------
// FINDING F-7 (LOW): Zero-byte policy layer treated same as missing layer
//
// A zero-byte blob for the policy layer causes json.Unmarshal to return
// "unexpected end of JSON input", which propagates as a hard error from
// parsePolicy. This is correct behavior after the F-1 fix.
// ----------------------------------------------------------------------------

func TestRedTeam_F7_ZeroBytePolicyLayer(t *testing.T) {
	policyJSON := ""
	policyDigest := digestOf(policyJSON)

	manifest := testManifest{
		Config: testDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []testDescriptor{
			{MediaType: "application/vnd.agentcontainers.orgpolicy.v1+json",
				Digest: policyDigest, Size: 0},
		},
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(manifest)
		case strings.Contains(r.URL.Path, "/blobs/"+policyDigest):
			// Zero bytes — digest of "" is valid.
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	ref := srv.Listener.Addr().String() + "/myorg/agent-base:latest"
	_, err := ExtractPolicy(context.Background(), ref, oci.WithHTTPClient(srv.Client()))

	// A zero-byte policy is a hard error (JSON parse fails on "").
	if err == nil {
		t.Errorf("VULNERABILITY F-7: zero-byte policy layer returned nil error — " +
			"JSON parse error was swallowed.")
	}
}
