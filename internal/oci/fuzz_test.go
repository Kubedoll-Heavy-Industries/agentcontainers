package oci

import (
	"encoding/json"
	"strings"
	"testing"
)

// FuzzFindPolicyLayer verifies that findPolicyLayer never panics on arbitrary
// adversary-controlled manifest bytes. The image manifest is fetched from a
// registry and decoded; a malicious registry operator could craft any JSON.
func FuzzFindPolicyLayer(f *testing.F) {
	// Seed: valid manifest with one policy layer.
	validWithPolicy, _ := json.Marshal(ociManifest{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Config:    ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []ociDescriptor{
			{
				MediaType: PolicyArtifactMediaType,
				Digest:    "sha256:abc123",
				Size:      42,
			},
		},
	})
	f.Add(validWithPolicy)

	// Seed: valid manifest without policy layer (non-policy media type only).
	withoutPolicy, _ := json.Marshal(ociManifest{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Config:    ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []ociDescriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
				Digest:    "sha256:def456",
				Size:      1024,
			},
		},
	})
	f.Add(withoutPolicy)

	// Seed: manifest with empty layers array.
	emptyLayers, _ := json.Marshal(ociManifest{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Config:    ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers:    []ociDescriptor{},
	})
	f.Add(emptyLayers)

	// Seed: malformed JSON.
	f.Add([]byte(`{`))
	f.Add([]byte(`}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`"string"`))
	f.Add([]byte(``))
	f.Add([]byte(`{"layers": "not-an-array"}`))
	f.Add([]byte(`{"layers": [{"mediaType": 42}]}`))

	// Seed: huge layers array (tests iteration over many entries without
	// hanging — findPolicyLayer is O(n) in layers, so large N is a concern).
	hugeManifest := `{"layers":[` + strings.Repeat(`{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:aaa","size":1},`, 9999) +
		`{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:bbb","size":1}]}`
	f.Add([]byte(hugeManifest))

	// Seed: annotation with policy signer set to garbage (exercises VerifyDescriptor path).
	withBadAnnotation, _ := json.Marshal(ociManifest{
		Layers: []ociDescriptor{
			{
				MediaType: PolicyArtifactMediaType,
				Digest:    "sha256:abc",
				Size:      1,
				Annotations: map[string]string{
					AnnotationOrgPolicySigner: `{"keyid":"not-hex","sig":"not-base64","algo":"ed25519"}`,
				},
			},
		},
	})
	f.Add(withBadAnnotation)

	f.Fuzz(func(t *testing.T, data []byte) {
		var m ociManifest
		if err := json.Unmarshal(data, &m); err != nil {
			// Unmarshal failure is expected for malformed input — not a bug.
			return
		}

		// findPolicyLayer must not panic regardless of manifest content.
		// We call with nil trustedKeys (first-wins mode) and then with strict=true
		// to exercise both branches.
		_, _ = findPolicyLayer(&m, nil, false)
		_, _ = findPolicyLayer(&m, nil, true)
	})
}
