package secrets

import "testing"

func TestParseSecretURI(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantScheme string
		wantRef    SecretRef
		wantOK     bool
	}{
		{
			name:       "1password op:// URI",
			input:      "op://vault-name/item-name/field-name",
			wantScheme: "1password",
			wantRef: SecretRef{
				Provider: "1password",
				Params: map[string]string{
					"vault": "vault-name",
					"item":  "item-name",
					"field": "field-name",
				},
			},
			wantOK: true,
		},
		{
			name:       "1password op:// without field",
			input:      "op://vault-name/item-name",
			wantScheme: "1password",
			wantRef: SecretRef{
				Provider: "1password",
				Params: map[string]string{
					"vault": "vault-name",
					"item":  "item-name",
				},
			},
			wantOK: true,
		},
		{
			name:       "vault:// URI",
			input:      "vault://myapp/config#api_key",
			wantScheme: "vault",
			wantRef: SecretRef{
				Provider: "vault",
				Params: map[string]string{
					"path": "myapp/config",
					"key":  "api_key",
				},
			},
			wantOK: true,
		},
		{
			name:       "vault:// without fragment key",
			input:      "vault://myapp/config",
			wantScheme: "vault",
			wantRef: SecretRef{
				Provider: "vault",
				Params: map[string]string{
					"path": "myapp/config",
				},
			},
			wantOK: true,
		},
		{
			name:       "infisical:// URI",
			input:      "infisical://project-id/production/DATABASE_URL",
			wantScheme: "infisical",
			wantRef: SecretRef{
				Provider: "infisical",
				Params: map[string]string{
					"projectID":   "project-id",
					"environment": "production",
					"secretName":  "DATABASE_URL",
				},
			},
			wantOK: true,
		},
		{
			name:       "env:// URI",
			input:      "env://MY_API_KEY",
			wantScheme: "env",
			wantRef: SecretRef{
				Provider: "env",
				Params: map[string]string{
					"env_var": "MY_API_KEY",
				},
			},
			wantOK: true,
		},
		{
			name:       "oidc:// URI",
			input:      "oidc://api.example.com",
			wantScheme: "oidc",
			wantRef: SecretRef{
				Provider: "oidc",
				Params: map[string]string{
					"audience": "api.example.com",
				},
			},
			wantOK: true,
		},
		{
			name:   "op:// vault-only is incomplete",
			input:  "op://vault-only",
			wantOK: false,
		},
		{
			name:   "infisical:// project-only is incomplete",
			input:  "infisical://proj",
			wantOK: false,
		},
		{
			name:   "infisical:// project+env is incomplete",
			input:  "infisical://proj/env",
			wantOK: false,
		},
		{
			name:   "plain value is not a URI",
			input:  "just-a-plain-value",
			wantOK: false,
		},
		{
			name:   "http is not a secret URI",
			input:  "http://example.com",
			wantOK: false,
		},
		{
			name:   "https is not a secret URI",
			input:  "https://example.com/secret",
			wantOK: false,
		},
		{
			name:   "empty string",
			input:  "",
			wantOK: false,
		},
		// Adversarial inputs.
		{
			name:       "path traversal in vault URI",
			input:      "vault://../../etc/shadow",
			wantScheme: "vault",
			wantRef: SecretRef{
				Provider: "vault",
				Params: map[string]string{
					"path": "../../etc/shadow",
				},
			},
			wantOK: true, // ParseSecretURI parses successfully; VaultProvider.Resolve rejects
		},
		{
			name:   "null byte in env URI",
			input:  "env://MY_VAR\x00INJECTED",
			wantOK: false, // null bytes are rejected — they truncate C strings at the OS boundary
		},
		{
			name:       "percent-encoded path in vault URI",
			input:      "vault://myapp%2Fconfig",
			wantScheme: "vault",
			wantRef: SecretRef{
				Provider: "vault",
				Params: map[string]string{
					"path": "myapp%2Fconfig",
				},
			},
			wantOK: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, ok := ParseSecretURI(tt.input)
			if ok != tt.wantOK {
				t.Fatalf("ParseSecretURI(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if ref.Provider != tt.wantRef.Provider {
				t.Errorf("Provider = %q, want %q", ref.Provider, tt.wantRef.Provider)
			}
			for k, v := range tt.wantRef.Params {
				if ref.Params[k] != v {
					t.Errorf("Params[%q] = %q, want %q", k, ref.Params[k], v)
				}
			}
			if len(ref.Params) != len(tt.wantRef.Params) {
				t.Errorf("Params length = %d, want %d (got %v)", len(ref.Params), len(tt.wantRef.Params), ref.Params)
			}
		})
	}
}

func TestIsSecretURI(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"op://vault/item/field", true},
		{"vault://secret/path", true},
		{"infisical://proj/env/name", true},
		{"env://MY_VAR", true},
		{"oidc://audience", true},
		{"http://example.com", false},
		{"just-a-string", false},
		{"", false},
		{"op://", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := IsSecretURI(tt.input); got != tt.want {
				t.Errorf("IsSecretURI(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
