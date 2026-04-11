package orgpolicy

import (
	"strings"
	"testing"
)

// FuzzParsePolicy verifies that parsePolicy never panics on arbitrary
// adversary-controlled JSON. The policy JSON is fetched from an OCI registry
// layer and passed directly to this parser; a malicious registry or a
// supply-chain attacker could craft any byte sequence.
func FuzzParsePolicy(f *testing.F) {
	// Seed: valid policy JSON with all fields populated.
	f.Add(`{
		"requireSignatures": true,
		"minSLSALevel": 2,
		"trustedRegistries": ["ghcr.io/myorg/*"],
		"bannedPackages": ["lodash@4.17.20"],
		"requireSBOM": true,
		"maxDriftThreshold": 0.5,
		"allowedCapabilities": ["exec", "network"],
		"deniedCapabilities": ["secrets"],
		"allowedFilesystemPaths": ["/data", "/workspace"],
		"allowedNetworkHosts": ["api.example.com", "*.internal.example.com"],
		"allowedMCPImages": ["ghcr.io/myorg/tools/"]
	}`)

	// Seed: minimal valid policy (empty object).
	f.Add(`{}`)

	// Seed: empty input.
	f.Add(``)

	// Seed: policy with removed maxAge field (should error, not panic).
	f.Add(`{"maxAge": "24h", "requireSignatures": true}`)

	// Seed: deeply nested objects (type confusion / stack overflow probing).
	f.Add(`{"trustedRegistries": {"nested": "object"}}`)
	f.Add(`{"minSLSALevel": "not-an-int"}`)
	f.Add(`{"maxDriftThreshold": "not-a-float"}`)
	f.Add(`{"requireSignatures": 1}`)
	f.Add(`{"allowedCapabilities": "string-not-array"}`)

	// Seed: out-of-range values for validated fields.
	f.Add(`{"minSLSALevel": -1}`)
	f.Add(`{"minSLSALevel": 5}`)
	f.Add(`{"maxDriftThreshold": -0.1}`)

	// Seed: unknown extra fields (strict parsing may reject; lenient may ignore).
	f.Add(`{"unknownField": "value", "requireSignatures": false}`)
	f.Add(`{"__proto__": {"admin": true}}`)

	// Seed: null field values.
	f.Add(`{"trustedRegistries": null}`)
	f.Add(`{"bannedPackages": null}`)

	// Seed: large arrays (performance / DoS check).
	bigArray := `{"trustedRegistries": [` + strings.Repeat(`"ghcr.io/myorg/*",`, 9999) + `"ghcr.io/other/*"]}`
	f.Add(bigArray)

	// Seed: unicode and control characters in string values.
	f.Add(`{"trustedRegistries": ["ghcr.io/\u0000org/*"]}`)
	f.Add(`{"bannedPackages": ["\u202e reversed"]}`)

	f.Fuzz(func(t *testing.T, data string) {
		// parsePolicy must never panic; it may return an error for invalid input.
		_, _ = parsePolicy([]byte(data))
	})
}
