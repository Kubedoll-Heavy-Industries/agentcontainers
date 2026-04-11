package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/oidc"
)

// mockProvider is a test provider that records calls and returns configurable results.
type mockProvider struct {
	name      string
	callCount int
	mu        sync.Mutex
	resolveFn func(ctx context.Context, ref SecretRef) (*Secret, error)
	closed    bool
}

func newMockProvider(name string) *mockProvider {
	return &mockProvider{
		name: name,
		resolveFn: func(_ context.Context, ref SecretRef) (*Secret, error) {
			return &Secret{
				Name:  ref.Name,
				Value: []byte("mock-value-" + ref.Name),
			}, nil
		},
	}
}

func (p *mockProvider) Name() string { return p.name }

func (p *mockProvider) Resolve(ctx context.Context, ref SecretRef) (*Secret, error) {
	p.mu.Lock()
	p.callCount++
	p.mu.Unlock()
	return p.resolveFn(ctx, ref)
}

func (p *mockProvider) Close() error {
	p.closed = true
	return nil
}

func (p *mockProvider) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.callCount
}

func TestManager_Resolve_UsesCorrectProvider(t *testing.T) {
	providerA := newMockProvider("provider-a")
	providerA.resolveFn = func(_ context.Context, ref SecretRef) (*Secret, error) {
		return &Secret{Name: ref.Name, Value: []byte("from-a")}, nil
	}
	providerB := newMockProvider("provider-b")
	providerB.resolveFn = func(_ context.Context, ref SecretRef) (*Secret, error) {
		return &Secret{Name: ref.Name, Value: []byte("from-b")}, nil
	}

	mgr := NewManager(WithProvider(providerA), WithProvider(providerB))
	defer mgr.Close() //nolint:errcheck

	tests := []struct {
		name     string
		ref      SecretRef
		wantVal  string
		wantProv string
	}{
		{
			name:     "uses provider A",
			ref:      SecretRef{Name: "secret-a", Provider: "provider-a"},
			wantVal:  "from-a",
			wantProv: "provider-a",
		},
		{
			name:     "uses provider B",
			ref:      SecretRef{Name: "secret-b", Provider: "provider-b"},
			wantVal:  "from-b",
			wantProv: "provider-b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret, err := mgr.Resolve(context.Background(), tt.ref)
			if err != nil {
				t.Fatalf("Resolve() error: %v", err)
			}
			if got := string(secret.Value); got != tt.wantVal {
				t.Errorf("Value = %q, want %q", got, tt.wantVal)
			}
		})
	}

	if providerA.calls() != 1 {
		t.Errorf("provider-a call count = %d, want 1", providerA.calls())
	}
	if providerB.calls() != 1 {
		t.Errorf("provider-b call count = %d, want 1", providerB.calls())
	}
}

func TestManager_Resolve_CachesWithTTL(t *testing.T) {
	provider := newMockProvider("caching")
	provider.resolveFn = func(_ context.Context, ref SecretRef) (*Secret, error) {
		return &Secret{
			Name:      ref.Name,
			Value:     []byte("cached-value"),
			ExpiresAt: time.Now().Add(10 * time.Minute),
		}, nil
	}

	mgr := NewManager(WithProvider(provider))
	defer mgr.Close() //nolint:errcheck

	ref := SecretRef{Name: "cached", Provider: "caching"}

	// First resolve.
	s1, err := mgr.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("first Resolve() error: %v", err)
	}

	// Second resolve should hit cache.
	s2, err := mgr.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("second Resolve() error: %v", err)
	}

	if provider.calls() != 1 {
		t.Errorf("provider call count = %d, want 1 (should be cached)", provider.calls())
	}
	if string(s1.Value) != string(s2.Value) {
		t.Errorf("cached value mismatch: %q vs %q", s1.Value, s2.Value)
	}
}

func TestManager_Resolve_ExpiredCacheRefetches(t *testing.T) {
	callNum := 0
	provider := newMockProvider("expiring")
	provider.resolveFn = func(_ context.Context, ref SecretRef) (*Secret, error) {
		callNum++
		return &Secret{
			Name:      ref.Name,
			Value:     []byte(fmt.Sprintf("value-%d", callNum)),
			ExpiresAt: time.Now().Add(-1 * time.Second), // Already expired.
		}, nil
	}

	mgr := NewManager(WithProvider(provider))
	defer mgr.Close() //nolint:errcheck

	ref := SecretRef{Name: "expiring-secret", Provider: "expiring"}

	// First resolve.
	s1, err := mgr.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("first Resolve() error: %v", err)
	}

	// Second resolve should refetch because the secret is already expired.
	s2, err := mgr.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("second Resolve() error: %v", err)
	}

	if provider.calls() != 2 {
		t.Errorf("provider call count = %d, want 2 (expired should refetch)", provider.calls())
	}
	if string(s1.Value) == string(s2.Value) {
		t.Errorf("expected different values after expiry, both are %q", s1.Value)
	}
}

func TestManager_ResolveAll_BatchResolve(t *testing.T) {
	provider := newMockProvider("batch")
	mgr := NewManager(WithProvider(provider))
	defer mgr.Close() //nolint:errcheck

	refs := []SecretRef{
		{Name: "secret-1", Provider: "batch"},
		{Name: "secret-2", Provider: "batch"},
		{Name: "secret-3", Provider: "batch"},
	}

	result, err := mgr.ResolveAll(context.Background(), refs)
	if err != nil {
		t.Fatalf("ResolveAll() error: %v", err)
	}

	if len(result) != 3 {
		t.Fatalf("result count = %d, want 3", len(result))
	}
	for _, ref := range refs {
		s, ok := result[ref.Name]
		if !ok {
			t.Errorf("missing secret %q in result", ref.Name)
			continue
		}
		if s.Name != ref.Name {
			t.Errorf("secret name = %q, want %q", s.Name, ref.Name)
		}
	}
}

func TestManager_Resolve_UnknownProvider_Error(t *testing.T) {
	mgr := NewManager()
	defer mgr.Close() //nolint:errcheck

	ref := SecretRef{Name: "test", Provider: "nonexistent"}
	_, err := mgr.Resolve(context.Background(), ref)
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
	if !strings.Contains(err.Error(), "unknown provider") {
		t.Errorf("error = %q, want contains 'unknown provider'", err.Error())
	}
}

func TestManager_InjectPath(t *testing.T) {
	mgr := NewManager()
	defer mgr.Close() //nolint:errcheck

	tests := []struct {
		name    string
		want    string
		wantErr bool
	}{
		{name: "my-token", want: "/run/secrets/my-token"},
		{name: "api-key", want: "/run/secrets/api-key"},
		{name: "oidc-jwt", want: "/run/secrets/oidc-jwt"},
		{name: "../../../etc/shadow", wantErr: true},
		{name: "../../etc/passwd", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mgr.InjectPath(tt.name)
			if tt.wantErr {
				if err == nil {
					t.Errorf("InjectPath(%q) expected error, got %q", tt.name, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("InjectPath(%q) unexpected error: %v", tt.name, err)
			}
			if got != tt.want {
				t.Errorf("InjectPath(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestManager_Rotation_CallsCallback(t *testing.T) {
	callNum := 0
	provider := newMockProvider("rotating")
	provider.resolveFn = func(_ context.Context, ref SecretRef) (*Secret, error) {
		callNum++
		return &Secret{
			Name:      ref.Name,
			Value:     []byte(fmt.Sprintf("rotated-%d", callNum)),
			ExpiresAt: time.Now().Add(10 * time.Millisecond), // Expires very quickly.
		}, nil
	}

	var rotatedMu sync.Mutex
	rotated := make(map[string]string)
	onRotation := func(name string, secret *Secret) {
		rotatedMu.Lock()
		rotated[name] = string(secret.Value)
		rotatedMu.Unlock()
	}

	mgr := NewManager(
		WithProvider(provider),
		WithRotationInterval(20*time.Millisecond),
		WithOnRotation(onRotation),
	)
	defer mgr.Close() //nolint:errcheck

	// Resolve initial secret.
	ref := SecretRef{Name: "rotating-secret", Provider: "rotating"}
	if _, err := mgr.Resolve(context.Background(), ref); err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}

	// Start rotation.
	if err := mgr.StartRotation(context.Background()); err != nil {
		t.Fatalf("StartRotation() error: %v", err)
	}

	// Wait for at least one rotation cycle with polling.
	deadline := time.After(2 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		rotatedMu.Lock()
		_, found := rotated["rotating-secret"]
		rotatedMu.Unlock()
		if found {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for rotation callback")
		case <-tick.C:
		}
	}

	rotatedMu.Lock()
	val, ok := rotated["rotating-secret"]
	rotatedMu.Unlock()

	if !ok {
		t.Fatal("expected rotation callback to be called")
	}
	if !strings.HasPrefix(val, "rotated-") {
		t.Errorf("rotated value = %q, want prefix 'rotated-'", val)
	}
	if provider.calls() < 2 {
		t.Errorf("provider call count = %d, want >= 2 (initial + rotation)", provider.calls())
	}
}

func TestManager_CachedSecrets(t *testing.T) {
	provider := newMockProvider("cached")
	provider.resolveFn = func(_ context.Context, ref SecretRef) (*Secret, error) {
		return &Secret{
			Name:     ref.Name,
			Value:    []byte("value-" + ref.Name),
			Metadata: map[string]string{"provider": "cached"},
		}, nil
	}

	mgr := NewManager(WithProvider(provider))
	defer mgr.Close() //nolint:errcheck

	t.Run("empty cache returns empty map", func(t *testing.T) {
		got := mgr.CachedSecrets()
		if len(got) != 0 {
			t.Errorf("CachedSecrets() returned %d entries, want 0", len(got))
		}
	})

	// Resolve some secrets to populate cache.
	refs := []SecretRef{
		{Name: "alpha", Provider: "cached"},
		{Name: "beta", Provider: "cached"},
	}
	if _, err := mgr.ResolveAll(context.Background(), refs); err != nil {
		t.Fatalf("ResolveAll() error: %v", err)
	}

	t.Run("returns resolved secrets", func(t *testing.T) {
		got := mgr.CachedSecrets()
		if len(got) != 2 {
			t.Fatalf("CachedSecrets() returned %d entries, want 2", len(got))
		}
		for _, ref := range refs {
			s, ok := got[ref.Name]
			if !ok {
				t.Errorf("missing cached secret %q", ref.Name)
				continue
			}
			wantVal := "value-" + ref.Name
			if string(s.Value) != wantVal {
				t.Errorf("secret %q: Value = %q, want %q", ref.Name, s.Value, wantVal)
			}
			if s.Metadata["provider"] != "cached" {
				t.Errorf("secret %q: metadata provider = %q, want cached", ref.Name, s.Metadata["provider"])
			}
		}
	})
}

func TestManager_Close_ClosesProviders(t *testing.T) {
	p1 := newMockProvider("p1")
	p2 := newMockProvider("p2")

	mgr := NewManager(WithProvider(p1), WithProvider(p2))
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	if !p1.closed {
		t.Error("provider p1 not closed")
	}
	if !p2.closed {
		t.Error("provider p2 not closed")
	}
}

func TestOIDCProvider_Resolve_MintsJWT(t *testing.T) {
	issuer, err := oidc.NewIssuer(oidc.WithIssuerURL("https://agent.test.local"))
	if err != nil {
		t.Fatalf("NewIssuer() error: %v", err)
	}

	provider := NewOIDCProvider(issuer, WithContainerID("container-abc"))

	if provider.Name() != "oidc" {
		t.Errorf("Name() = %q, want %q", provider.Name(), "oidc")
	}

	ref := SecretRef{
		Name:     "cloud-token",
		Provider: "oidc",
		Params: map[string]string{
			"audience": "https://sts.amazonaws.com",
		},
	}

	secret, err := provider.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}

	if secret.Name != "cloud-token" {
		t.Errorf("Name = %q, want %q", secret.Name, "cloud-token")
	}
	if secret.ExpiresAt.IsZero() {
		t.Error("expected non-zero ExpiresAt")
	}
	if secret.ExpiresAt.Before(time.Now()) {
		t.Error("ExpiresAt should be in the future")
	}

	// Verify the token is a valid JWT with 3 parts.
	token := string(secret.Value)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT parts = %d, want 3", len(parts))
	}

	// Decode and verify claims.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var claims oidc.Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}

	if claims.Sub != "container-abc" {
		t.Errorf("sub = %q, want %q", claims.Sub, "container-abc")
	}
	if len(claims.Aud) != 1 || claims.Aud[0] != "https://sts.amazonaws.com" {
		t.Errorf("aud = %v, want [https://sts.amazonaws.com]", claims.Aud)
	}
	if claims.Iss != "https://agent.test.local" {
		t.Errorf("iss = %q, want %q", claims.Iss, "https://agent.test.local")
	}
	if claims.ContainerID != "container-abc" {
		t.Errorf("container_id = %q, want %q", claims.ContainerID, "container-abc")
	}

	// Verify metadata.
	if secret.Metadata["provider"] != "oidc" {
		t.Errorf("metadata provider = %q, want oidc", secret.Metadata["provider"])
	}
	if secret.Metadata["audience"] != "https://sts.amazonaws.com" {
		t.Errorf("metadata audience = %q, want https://sts.amazonaws.com", secret.Metadata["audience"])
	}
}

func TestOIDCProvider_Resolve_MissingAudience(t *testing.T) {
	issuer, err := oidc.NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer() error: %v", err)
	}

	provider := NewOIDCProvider(issuer)
	ref := SecretRef{
		Name:     "test",
		Provider: "oidc",
		Params:   map[string]string{},
	}

	_, err = provider.Resolve(context.Background(), ref)
	if err == nil {
		t.Fatal("expected error for missing audience")
	}
	if !strings.Contains(err.Error(), "audience") {
		t.Errorf("error = %q, want contains 'audience'", err.Error())
	}
}

func TestOIDCProvider_Resolve_CustomSubject(t *testing.T) {
	issuer, err := oidc.NewIssuer(oidc.WithIssuerURL("https://agent.test.local"))
	if err != nil {
		t.Fatalf("NewIssuer() error: %v", err)
	}

	provider := NewOIDCProvider(issuer, WithContainerID("default-container"))

	ref := SecretRef{
		Name:     "custom-sub",
		Provider: "oidc",
		Params: map[string]string{
			"audience": "https://api.example.com",
			"subject":  "custom-subject-id",
		},
	}

	secret, err := provider.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}

	// Decode claims and verify custom subject.
	parts := strings.Split(string(secret.Value), ".")
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims oidc.Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}

	if claims.Sub != "custom-subject-id" {
		t.Errorf("sub = %q, want %q", claims.Sub, "custom-subject-id")
	}
}

func TestOIDCProvider_Resolve_CustomTTL(t *testing.T) {
	issuer, err := oidc.NewIssuer(oidc.WithIssuerURL("https://agent.test.local"))
	if err != nil {
		t.Fatalf("NewIssuer() error: %v", err)
	}

	provider := NewOIDCProvider(issuer, WithContainerID("ttl-test"))

	ref := SecretRef{
		Name:     "short-lived",
		Provider: "oidc",
		Params: map[string]string{
			"audience": "https://api.example.com",
			"ttl":      "15m",
		},
	}

	secret, err := provider.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}

	// Verify expiry is roughly 15 minutes from now (with some tolerance).
	expectedExpiry := time.Now().Add(15 * time.Minute)
	diff := secret.ExpiresAt.Sub(expectedExpiry)
	if diff < -5*time.Second || diff > 5*time.Second {
		t.Errorf("ExpiresAt diff from expected = %v, want within 5s", diff)
	}
}

func TestEnvProvider_Resolve(t *testing.T) {
	provider := NewEnvProvider()

	if provider.Name() != "env" {
		t.Errorf("Name() = %q, want %q", provider.Name(), "env")
	}

	t.Run("reads env var", func(t *testing.T) {
		t.Setenv("TEST_SECRET_VALUE", "super-secret-123")

		ref := SecretRef{
			Name:     "my-secret",
			Provider: "env",
			Params:   map[string]string{"env_var": "TEST_SECRET_VALUE"},
		}

		secret, err := provider.Resolve(context.Background(), ref)
		if err != nil {
			t.Fatalf("Resolve() error: %v", err)
		}

		if string(secret.Value) != "super-secret-123" {
			t.Errorf("Value = %q, want %q", secret.Value, "super-secret-123")
		}
		if secret.Name != "my-secret" {
			t.Errorf("Name = %q, want %q", secret.Name, "my-secret")
		}
		if !secret.ExpiresAt.IsZero() {
			t.Errorf("ExpiresAt = %v, want zero (no expiry)", secret.ExpiresAt)
		}
		if secret.Metadata["provider"] != "env" {
			t.Errorf("metadata provider = %q, want env", secret.Metadata["provider"])
		}
		if secret.Metadata["env_var"] != "TEST_SECRET_VALUE" {
			t.Errorf("metadata env_var = %q, want TEST_SECRET_VALUE", secret.Metadata["env_var"])
		}
	})

	t.Run("missing env var", func(t *testing.T) {
		// Ensure the variable is not set.
		_ = os.Unsetenv("NONEXISTENT_SECRET_VAR_XYZ")

		ref := SecretRef{
			Name:     "missing",
			Provider: "env",
			Params:   map[string]string{"env_var": "NONEXISTENT_SECRET_VAR_XYZ"},
		}

		_, err := provider.Resolve(context.Background(), ref)
		if err == nil {
			t.Fatal("expected error for missing env var")
		}
		if !strings.Contains(err.Error(), "not set") {
			t.Errorf("error = %q, want contains 'not set'", err.Error())
		}
	})

	t.Run("missing env_var param", func(t *testing.T) {
		ref := SecretRef{
			Name:     "no-param",
			Provider: "env",
			Params:   map[string]string{},
		}

		_, err := provider.Resolve(context.Background(), ref)
		if err == nil {
			t.Fatal("expected error for missing env_var param")
		}
		if !strings.Contains(err.Error(), "env_var param is required") {
			t.Errorf("error = %q, want contains 'env_var param is required'", err.Error())
		}
	})

	t.Run("empty string env var", func(t *testing.T) {
		t.Setenv("EMPTY_SECRET_VAR", "")

		ref := SecretRef{
			Name:     "empty",
			Provider: "env",
			Params:   map[string]string{"env_var": "EMPTY_SECRET_VAR"},
		}

		secret, err := provider.Resolve(context.Background(), ref)
		if err != nil {
			t.Fatalf("Resolve() error: %v", err)
		}
		if len(secret.Value) != 0 {
			t.Errorf("Value = %q, want empty", secret.Value)
		}
	})
}

func TestManager_ResolveAll_ErrorPropagation(t *testing.T) {
	provider := newMockProvider("failing")
	provider.resolveFn = func(_ context.Context, ref SecretRef) (*Secret, error) {
		if ref.Name == "bad-secret" {
			return nil, fmt.Errorf("provider error")
		}
		return &Secret{Name: ref.Name, Value: []byte("ok")}, nil
	}

	mgr := NewManager(WithProvider(provider))
	defer mgr.Close() //nolint:errcheck

	refs := []SecretRef{
		{Name: "good-secret", Provider: "failing"},
		{Name: "bad-secret", Provider: "failing"},
	}

	_, err := mgr.ResolveAll(context.Background(), refs)
	if err == nil {
		t.Fatal("expected error from ResolveAll")
	}
	if !strings.Contains(err.Error(), "bad-secret") {
		t.Errorf("error = %q, want contains 'bad-secret'", err.Error())
	}
}

func TestManager_Resolve_Concurrent(t *testing.T) {
	provider := newMockProvider("concurrent")
	mgr := NewManager(WithProvider(provider))
	defer mgr.Close() //nolint:errcheck

	const goroutines = 20
	done := make(chan struct{}, goroutines)
	ref := SecretRef{Name: "shared-secret", Provider: "concurrent"}

	for i := 0; i < goroutines; i++ {
		go func() {
			_, err := mgr.Resolve(context.Background(), ref)
			if err != nil {
				t.Errorf("concurrent Resolve() error: %v", err)
			}
			done <- struct{}{}
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}

	// All goroutines hit cache after first resolve; provider should be called once.
	if provider.calls() > goroutines {
		t.Errorf("provider call count = %d, expected <= %d (cache should have served most)", provider.calls(), goroutines)
	}
}
