package secrets

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzParseSecretURI verifies that ParseSecretURI never panics on arbitrary
// adversary-controlled input. The fuzzer should not crash or hang; returning
// false / SecretRef{} for invalid input is correct behavior.
func FuzzParseSecretURI(f *testing.F) {
	// Seed: valid URIs for all 5 supported schemes.
	f.Add("op://myvault/myitem/myfield")
	f.Add("op://myvault/myitem")
	f.Add("vault://secret/data/myapp#password")
	f.Add("vault://secret/data/myapp")
	f.Add("infisical://proj123/production/DB_PASS")
	f.Add("env://MY_ENV_VAR")
	f.Add("oidc://my-audience")

	// Seed: empty / boundary cases.
	f.Add("")
	f.Add("op://")
	f.Add("vault://")
	f.Add("infisical://")
	f.Add("env://")
	f.Add("oidc://")

	// Seed: path traversal attempts.
	f.Add("vault://../../etc/passwd")
	f.Add("op://../../../etc/shadow/item")
	f.Add("env://../relative")

	// Seed: null bytes.
	f.Add("env://VAR\x00NAME")
	f.Add("op://vault\x00/item/field")

	// Seed: percent-encoded characters.
	f.Add("vault://secret%2Fpath/key%40value")
	f.Add("infisical://proj%20id/env%00/name")

	// Seed: multi-megabyte string (tests length handling without hanging).
	f.Add("vault://" + strings.Repeat("a", 2<<20))

	// Seed: unknown scheme (should return false cleanly).
	f.Add("s3://bucket/key")
	f.Add("https://example.com/secret")
	f.Add("://missing-scheme")

	f.Fuzz(func(t *testing.T, data string) {
		// Must not panic; must handle all valid UTF-8 and arbitrary bytes.
		// The function is allowed to return (SecretRef{}, false) for any input.
		ref, ok := ParseSecretURI(data)

		// If ok is true, the returned ref must have a non-empty Provider.
		if ok && ref.Provider == "" {
			t.Errorf("ParseSecretURI returned ok=true but Provider is empty for input %q", data)
		}

		// If ok is true, the input must start with one of the known schemes.
		if ok {
			matched := false
			for prefix := range supportedSchemes {
				if strings.HasPrefix(data, prefix) {
					matched = true
					break
				}
			}
			if !matched {
				t.Errorf("ParseSecretURI returned ok=true for input with no known scheme prefix: %q", data)
			}
		}

		// Params map must never be nil when ok is true.
		if ok && ref.Params == nil {
			t.Errorf("ParseSecretURI returned ok=true but Params is nil for input %q", data)
		}

		// No value in Params should contain a null byte — these come from
		// user-controlled data and would be misinterpreted by C-string
		// consumers (e.g. env injection via execve).
		if ok {
			for k, v := range ref.Params {
				if strings.ContainsRune(v, 0) {
					t.Errorf("Params[%q] contains null byte for input %q", k, data)
				}
				if !utf8.ValidString(v) {
					// Non-UTF-8 param values could cause issues in JSON serialization.
					t.Errorf("Params[%q] is not valid UTF-8 for input %q", k, data)
				}
			}
		}
	})
}
