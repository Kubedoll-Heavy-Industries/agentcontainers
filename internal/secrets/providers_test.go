package secrets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// --- Vault Provider Tests ---

func TestVaultProvider_Resolve_ReadsSecret(t *testing.T) {
	// Mock a Vault KV v2 response with full data.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.URL.Path != "/v1/secret/data/myapp/config" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		resp := map[string]any{
			"data": map[string]any{
				"data": map[string]any{
					"username": "admin",
					"password": "s3cret",
				},
				"metadata": map[string]any{
					"version": 1,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	provider := NewVaultProvider(
		WithVaultAddr(srv.URL),
		WithVaultToken("test-token"),
		WithVaultHTTPClient(srv.Client()),
	)

	if provider.Name() != "vault" {
		t.Errorf("Name() = %q, want %q", provider.Name(), "vault")
	}

	ref := SecretRef{
		Name:     "db-creds",
		Provider: "vault",
		Params: map[string]string{
			"path": "myapp/config",
		},
	}

	secret, err := provider.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}

	if secret.Name != "db-creds" {
		t.Errorf("Name = %q, want %q", secret.Name, "db-creds")
	}

	// The value should be the full data as JSON.
	var data map[string]any
	if err := json.Unmarshal(secret.Value, &data); err != nil {
		t.Fatalf("unmarshal value: %v", err)
	}
	if data["username"] != "admin" {
		t.Errorf("username = %v, want admin", data["username"])
	}
	if data["password"] != "s3cret" {
		t.Errorf("password = %v, want s3cret", data["password"])
	}

	if !secret.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt = %v, want zero (Vault manages leases)", secret.ExpiresAt)
	}
	if secret.Metadata["provider"] != "vault" {
		t.Errorf("metadata provider = %q, want vault", secret.Metadata["provider"])
	}
	if secret.Metadata["path"] != "myapp/config" {
		t.Errorf("metadata path = %q, want myapp/config", secret.Metadata["path"])
	}
}

func TestVaultProvider_Resolve_SpecificKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"data": map[string]any{
				"data": map[string]any{
					"api_key":  "key-abc-123",
					"api_host": "api.example.com",
				},
				"metadata": map[string]any{
					"version": 2,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	provider := NewVaultProvider(
		WithVaultAddr(srv.URL),
		WithVaultToken("t"),
		WithVaultHTTPClient(srv.Client()),
	)

	tests := []struct {
		name    string
		key     string
		wantVal string
	}{
		{
			name:    "extracts api_key",
			key:     "api_key",
			wantVal: "key-abc-123",
		},
		{
			name:    "extracts api_host",
			key:     "api_host",
			wantVal: "api.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := SecretRef{
				Name:     "test",
				Provider: "vault",
				Params: map[string]string{
					"path": "app/keys",
					"key":  tt.key,
				},
			}
			secret, err := provider.Resolve(context.Background(), ref)
			if err != nil {
				t.Fatalf("Resolve() error: %v", err)
			}
			if got := string(secret.Value); got != tt.wantVal {
				t.Errorf("Value = %q, want %q", got, tt.wantVal)
			}
		})
	}
}

func TestVaultProvider_Resolve_MissingPath(t *testing.T) {
	provider := NewVaultProvider(
		WithVaultAddr("http://localhost:8200"),
		WithVaultToken("t"),
	)

	ref := SecretRef{
		Name:     "test",
		Provider: "vault",
		Params:   map[string]string{},
	}

	_, err := provider.Resolve(context.Background(), ref)
	if err == nil {
		t.Fatal("expected error for missing path param")
	}
	if !strings.Contains(err.Error(), "path param is required") {
		t.Errorf("error = %q, want contains 'path param is required'", err.Error())
	}
}

func TestVaultProvider_Resolve_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
	}))
	defer srv.Close()

	provider := NewVaultProvider(
		WithVaultAddr(srv.URL),
		WithVaultToken("bad-token"),
		WithVaultHTTPClient(srv.Client()),
	)

	ref := SecretRef{
		Name:     "test",
		Provider: "vault",
		Params: map[string]string{
			"path": "secret/path",
		},
	}

	_, err := provider.Resolve(context.Background(), ref)
	if err == nil {
		t.Fatal("expected error for HTTP 403")
	}
	if !strings.Contains(err.Error(), "HTTP 403") {
		t.Errorf("error = %q, want contains 'HTTP 403'", err.Error())
	}
}

func TestVaultProvider_Resolve_CustomMount(t *testing.T) {
	var requestedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		resp := map[string]any{
			"data": map[string]any{
				"data":     map[string]any{"val": "ok"},
				"metadata": map[string]any{},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	provider := NewVaultProvider(
		WithVaultAddr(srv.URL),
		WithVaultToken("t"),
		WithVaultHTTPClient(srv.Client()),
	)

	ref := SecretRef{
		Name:     "test",
		Provider: "vault",
		Params: map[string]string{
			"path":  "app/db",
			"mount": "kv",
		},
	}

	_, err := provider.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if requestedPath != "/v1/kv/data/app/db" {
		t.Errorf("requested path = %q, want /v1/kv/data/app/db", requestedPath)
	}
}

func TestVaultProvider_Resolve_Version(t *testing.T) {
	var requestedQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedQuery = r.URL.RawQuery
		resp := map[string]any{
			"data": map[string]any{
				"data":     map[string]any{"val": "v3"},
				"metadata": map[string]any{},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	provider := NewVaultProvider(
		WithVaultAddr(srv.URL),
		WithVaultToken("t"),
		WithVaultHTTPClient(srv.Client()),
	)

	ref := SecretRef{
		Name:     "test",
		Provider: "vault",
		Params: map[string]string{
			"path":    "app/db",
			"version": "3",
		},
	}

	_, err := provider.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if requestedQuery != "version=3" {
		t.Errorf("query = %q, want version=3", requestedQuery)
	}
}

func TestVaultProvider_Resolve_KeyNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"data": map[string]any{
				"data":     map[string]any{"existing": "value"},
				"metadata": map[string]any{},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	provider := NewVaultProvider(
		WithVaultAddr(srv.URL),
		WithVaultToken("t"),
		WithVaultHTTPClient(srv.Client()),
	)

	ref := SecretRef{
		Name:     "test",
		Provider: "vault",
		Params: map[string]string{
			"path": "app/db",
			"key":  "nonexistent",
		},
	}

	_, err := provider.Resolve(context.Background(), ref)
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	if !strings.Contains(err.Error(), "key \"nonexistent\" not found") {
		t.Errorf("error = %q, want contains key not found message", err.Error())
	}
}

func TestVaultProvider_Close(t *testing.T) {
	provider := NewVaultProvider()
	if err := provider.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}
}

// --- Infisical Provider Tests ---

func TestInfisicalProvider_Resolve_AuthenticatesAndReads(t *testing.T) {
	var authCalls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/api/v1/auth/universal-auth/login" && r.Method == http.MethodPost:
			authCalls.Add(1)

			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if body["clientId"] != "test-client-id" || body["clientSecret"] != "test-client-secret" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"accessToken":       "test-access-token",
				"expiresIn":         7200,
				"accessTokenMaxTTL": 86400,
				"tokenType":         "Bearer",
			})

		case strings.HasPrefix(r.URL.Path, "/api/v3/secrets/raw/"):
			if r.Header.Get("Authorization") != "Bearer test-access-token" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			secretName := strings.TrimPrefix(r.URL.Path, "/api/v3/secrets/raw/")
			env := r.URL.Query().Get("environment")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"secret": map[string]any{
					"id":          "sec-123",
					"secretKey":   secretName,
					"secretValue": "super-secret-value",
					"version":     1,
					"environment": env,
					"workspace":   "ws-456",
					"secretPath":  "/",
				},
			})

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	provider := NewInfisicalProvider(
		WithInfisicalAddr(srv.URL),
		WithInfisicalAuth("test-client-id", "test-client-secret"),
		WithInfisicalHTTPClient(srv.Client()),
	)

	if provider.Name() != "infisical" {
		t.Errorf("Name() = %q, want %q", provider.Name(), "infisical")
	}

	ref := SecretRef{
		Name:     "my-secret",
		Provider: "infisical",
		Params: map[string]string{
			"secretName":  "DB_PASSWORD",
			"environment": "prod",
			"projectID":   "ws-456",
		},
	}

	secret, err := provider.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}

	if secret.Name != "my-secret" {
		t.Errorf("Name = %q, want %q", secret.Name, "my-secret")
	}
	if got := string(secret.Value); got != "super-secret-value" {
		t.Errorf("Value = %q, want %q", got, "super-secret-value")
	}
	if !secret.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt = %v, want zero", secret.ExpiresAt)
	}
	if secret.Metadata["provider"] != "infisical" {
		t.Errorf("metadata provider = %q, want infisical", secret.Metadata["provider"])
	}
	if secret.Metadata["environment"] != "prod" {
		t.Errorf("metadata environment = %q, want prod", secret.Metadata["environment"])
	}

	if authCalls.Load() != 1 {
		t.Errorf("auth call count = %d, want 1", authCalls.Load())
	}
}

func TestInfisicalProvider_Resolve_CachesToken(t *testing.T) {
	var authCalls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/api/v1/auth/universal-auth/login":
			authCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"accessToken": "cached-token",
				"expiresIn":   7200,
				"tokenType":   "Bearer",
			})

		case strings.HasPrefix(r.URL.Path, "/api/v3/secrets/raw/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"secret": map[string]any{
					"secretKey":   "KEY",
					"secretValue": "value",
					"version":     1,
				},
			})

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	provider := NewInfisicalProvider(
		WithInfisicalAddr(srv.URL),
		WithInfisicalAuth("id", "secret"),
		WithInfisicalHTTPClient(srv.Client()),
	)

	ref := SecretRef{
		Name:     "test",
		Provider: "infisical",
		Params: map[string]string{
			"secretName":  "KEY",
			"environment": "dev",
		},
	}

	// Call Resolve twice.
	if _, err := provider.Resolve(context.Background(), ref); err != nil {
		t.Fatalf("first Resolve() error: %v", err)
	}
	if _, err := provider.Resolve(context.Background(), ref); err != nil {
		t.Fatalf("second Resolve() error: %v", err)
	}

	// Auth should only have been called once.
	if authCalls.Load() != 1 {
		t.Errorf("auth call count = %d, want 1 (token should be cached)", authCalls.Load())
	}
}

func TestInfisicalProvider_Resolve_MissingParams(t *testing.T) {
	provider := NewInfisicalProvider(
		WithInfisicalAddr("http://localhost"),
		WithInfisicalAuth("id", "secret"),
	)

	tests := []struct {
		name      string
		params    map[string]string
		wantError string
	}{
		{
			name:      "missing secretName",
			params:    map[string]string{"environment": "prod"},
			wantError: "secretName param is required",
		},
		{
			name:      "missing environment",
			params:    map[string]string{"secretName": "KEY"},
			wantError: "environment param is required",
		},
		{
			name:      "both missing",
			params:    map[string]string{},
			wantError: "secretName param is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := SecretRef{
				Name:     "test",
				Provider: "infisical",
				Params:   tt.params,
			}
			_, err := provider.Resolve(context.Background(), ref)
			if err == nil {
				t.Fatal("expected error for missing params")
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("error = %q, want contains %q", err.Error(), tt.wantError)
			}
		})
	}
}

func TestInfisicalProvider_Close(t *testing.T) {
	provider := NewInfisicalProvider()
	if err := provider.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}
}

// --- OnePassword Provider Tests ---

func TestOnePasswordProvider_Resolve_ReadsField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer op-token-123" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/v1/vaults/my-vault/items/login-item" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		resp := map[string]any{
			"id":    "item-abc",
			"title": "Login Item",
			"fields": []map[string]any{
				{"id": "username-field", "label": "username", "value": "admin", "type": "STRING"},
				{"id": "password-field", "label": "password", "value": "p@ssw0rd!", "type": "CONCEALED", "purpose": "PASSWORD"},
				{"id": "notes-field", "label": "notesPlain", "value": "some notes", "type": "STRING"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	provider := NewOnePasswordProvider(
		WithOnePasswordAddr(srv.URL),
		WithOnePasswordToken("op-token-123"),
		WithOnePasswordHTTPClient(srv.Client()),
	)

	if provider.Name() != "1password" {
		t.Errorf("Name() = %q, want %q", provider.Name(), "1password")
	}

	ref := SecretRef{
		Name:     "login-password",
		Provider: "1password",
		Params: map[string]string{
			"vault": "my-vault",
			"item":  "login-item",
		},
	}

	secret, err := provider.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}

	if secret.Name != "login-password" {
		t.Errorf("Name = %q, want %q", secret.Name, "login-password")
	}
	// Default field is "password".
	if got := string(secret.Value); got != "p@ssw0rd!" {
		t.Errorf("Value = %q, want %q", got, "p@ssw0rd!")
	}
	if !secret.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt = %v, want zero", secret.ExpiresAt)
	}
	if secret.Metadata["provider"] != "1password" {
		t.Errorf("metadata provider = %q, want 1password", secret.Metadata["provider"])
	}
	if secret.Metadata["vault"] != "my-vault" {
		t.Errorf("metadata vault = %q, want my-vault", secret.Metadata["vault"])
	}
	if secret.Metadata["item"] != "login-item" {
		t.Errorf("metadata item = %q, want login-item", secret.Metadata["item"])
	}
	if secret.Metadata["field"] != "password" {
		t.Errorf("metadata field = %q, want password", secret.Metadata["field"])
	}
}

func TestOnePasswordProvider_Resolve_CustomField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"id":    "item-def",
			"title": "API Credentials",
			"fields": []map[string]any{
				{"id": "f1", "label": "password", "value": "default-pw", "type": "CONCEALED"},
				{"id": "f2", "label": "api_token", "value": "tok-xyz-789", "type": "CONCEALED"},
				{"id": "f3", "label": "endpoint", "value": "https://api.example.com", "type": "STRING"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	provider := NewOnePasswordProvider(
		WithOnePasswordAddr(srv.URL),
		WithOnePasswordToken("t"),
		WithOnePasswordHTTPClient(srv.Client()),
	)

	tests := []struct {
		name    string
		field   string
		wantVal string
	}{
		{
			name:    "api_token field",
			field:   "api_token",
			wantVal: "tok-xyz-789",
		},
		{
			name:    "endpoint field",
			field:   "endpoint",
			wantVal: "https://api.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := SecretRef{
				Name:     "test",
				Provider: "1password",
				Params: map[string]string{
					"vault": "v",
					"item":  "i",
					"field": tt.field,
				},
			}
			secret, err := provider.Resolve(context.Background(), ref)
			if err != nil {
				t.Fatalf("Resolve() error: %v", err)
			}
			if got := string(secret.Value); got != tt.wantVal {
				t.Errorf("Value = %q, want %q", got, tt.wantVal)
			}
		})
	}
}

func TestOnePasswordProvider_Resolve_MissingParams(t *testing.T) {
	provider := NewOnePasswordProvider(
		WithOnePasswordAddr("http://localhost"),
		WithOnePasswordToken("t"),
	)

	tests := []struct {
		name      string
		params    map[string]string
		wantError string
	}{
		{
			name:      "missing vault",
			params:    map[string]string{"item": "i"},
			wantError: "vault param is required",
		},
		{
			name:      "missing item",
			params:    map[string]string{"vault": "v"},
			wantError: "item param is required",
		},
		{
			name:      "both missing",
			params:    map[string]string{},
			wantError: "vault param is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := SecretRef{
				Name:     "test",
				Provider: "1password",
				Params:   tt.params,
			}
			_, err := provider.Resolve(context.Background(), ref)
			if err == nil {
				t.Fatal("expected error for missing params")
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("error = %q, want contains %q", err.Error(), tt.wantError)
			}
		})
	}
}

func TestOnePasswordProvider_Resolve_FieldNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"id":    "item-abc",
			"title": "Test",
			"fields": []map[string]any{
				{"id": "f1", "label": "username", "value": "user", "type": "STRING"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	provider := NewOnePasswordProvider(
		WithOnePasswordAddr(srv.URL),
		WithOnePasswordToken("t"),
		WithOnePasswordHTTPClient(srv.Client()),
	)

	ref := SecretRef{
		Name:     "test",
		Provider: "1password",
		Params: map[string]string{
			"vault": "v",
			"item":  "i",
			"field": "nonexistent",
		},
	}

	_, err := provider.Resolve(context.Background(), ref)
	if err == nil {
		t.Fatal("expected error for field not found")
	}
	if !strings.Contains(err.Error(), "field \"nonexistent\" not found") {
		t.Errorf("error = %q, want contains field not found message", err.Error())
	}
}

func TestOnePasswordProvider_Resolve_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	provider := NewOnePasswordProvider(
		WithOnePasswordAddr(srv.URL),
		WithOnePasswordToken("bad-token"),
		WithOnePasswordHTTPClient(srv.Client()),
	)

	ref := SecretRef{
		Name:     "test",
		Provider: "1password",
		Params: map[string]string{
			"vault": "v",
			"item":  "i",
		},
	}

	_, err := provider.Resolve(context.Background(), ref)
	if err == nil {
		t.Fatal("expected error for HTTP 401")
	}
	if !strings.Contains(err.Error(), "HTTP 401") {
		t.Errorf("error = %q, want contains 'HTTP 401'", err.Error())
	}
}

func TestOnePasswordProvider_Close(t *testing.T) {
	provider := NewOnePasswordProvider()
	if err := provider.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}
}
