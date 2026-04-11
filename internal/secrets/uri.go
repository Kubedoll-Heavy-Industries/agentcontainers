package secrets

import (
	"strings"
	"unicode/utf8"
)

// supportedSchemes maps URI scheme prefixes to provider names.
var supportedSchemes = map[string]string{
	"op://":        "1password",
	"vault://":     "vault",
	"infisical://": "infisical",
	"env://":       "env",
	"oidc://":      "oidc",
}

// ParseSecretURI attempts to parse a secret value as a provider-specific URI.
// Returns the parsed SecretRef and true if the value matches a known scheme,
// or a zero SecretRef and false otherwise.
//
// Null bytes and non-UTF-8 sequences are rejected unconditionally. Null bytes
// terminate C strings at the OS boundary (execve, open) and would silently
// truncate parameter values passed to provider CLIs or environment variables.
// Non-UTF-8 bytes would produce malformed JSON when params are serialized and
// could be misinterpreted by downstream Go string operations.
func ParseSecretURI(value string) (SecretRef, bool) {
	if strings.ContainsRune(value, 0) || !utf8.ValidString(value) {
		return SecretRef{}, false
	}
	for prefix, provider := range supportedSchemes {
		if strings.HasPrefix(value, prefix) {
			body := strings.TrimPrefix(value, prefix)
			if body == "" {
				return SecretRef{}, false
			}
			ref, valid := parseSchemeBody(provider, body)
			if !valid {
				return SecretRef{}, false
			}
			return ref, true
		}
	}
	return SecretRef{}, false
}

func parseSchemeBody(provider, body string) (SecretRef, bool) {
	ref := SecretRef{
		Provider: provider,
		Params:   make(map[string]string),
	}

	switch provider {
	case "1password":
		// op://vault/item[/field]
		parts := strings.SplitN(body, "/", 3)
		if len(parts) < 2 {
			return SecretRef{}, false // vault and item are required
		}
		ref.Params["vault"] = parts[0]
		ref.Params["item"] = parts[1]
		if len(parts) >= 3 {
			ref.Params["field"] = parts[2]
		}

	case "vault":
		// vault://path/to/secret[#key]
		path := body
		if idx := strings.LastIndex(path, "#"); idx != -1 {
			ref.Params["key"] = path[idx+1:]
			path = path[:idx]
		}
		ref.Params["path"] = path

	case "infisical":
		// infisical://projectID/environment/secretName
		parts := strings.SplitN(body, "/", 3)
		if len(parts) < 3 {
			return SecretRef{}, false // projectID, environment, secretName all required
		}
		ref.Params["projectID"] = parts[0]
		ref.Params["environment"] = parts[1]
		ref.Params["secretName"] = parts[2]

	case "env":
		ref.Params["env_var"] = body

	case "oidc":
		ref.Params["audience"] = body
	}

	return ref, true
}

// IsSecretURI returns true if the value looks like a secret URI reference.
func IsSecretURI(value string) bool {
	for prefix := range supportedSchemes {
		if _, ok := strings.CutPrefix(value, prefix); ok {
			return value != prefix
		}
	}
	return false
}
