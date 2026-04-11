package secrets

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"
)

const (
	// defaultRotationInterval is the default interval for checking secret TTLs.
	defaultRotationInterval = 5 * time.Minute

	// secretsBasePath is the base path where secrets are mounted inside containers.
	secretsBasePath = "/run/secrets"
)

// ManagerOption configures a Manager.
type ManagerOption func(*Manager)

// WithProvider registers a secret provider with the manager.
func WithProvider(p Provider) ManagerOption {
	return func(m *Manager) {
		m.providers[p.Name()] = p
	}
}

// WithRotationInterval sets the interval for TTL rotation checks.
func WithRotationInterval(d time.Duration) ManagerOption {
	return func(m *Manager) {
		m.rotationInterval = d
	}
}

// WithOnRotation registers a callback invoked when a secret is rotated.
// The callback receives the secret name and the newly resolved secret.
func WithOnRotation(fn func(name string, secret *Secret)) ManagerOption {
	return func(m *Manager) {
		m.onRotation = fn
	}
}

// Manager orchestrates secret resolution, caching, TTL-based rotation,
// and container mount generation.
type Manager struct {
	providers        map[string]Provider
	rotationInterval time.Duration
	onRotation       func(name string, secret *Secret)

	mu    sync.RWMutex
	cache map[string]*cacheEntry

	// refs stores the original SecretRef for each cached secret, needed for
	// re-resolution during rotation.
	refs map[string]SecretRef

	cancel context.CancelFunc
	done   chan struct{}
}

// cacheEntry holds a cached secret and its resolution metadata.
type cacheEntry struct {
	secret     *Secret
	resolvedAt time.Time
}

// NewManager creates a new secrets Manager with the given options.
func NewManager(opts ...ManagerOption) *Manager {
	m := &Manager{
		providers:        make(map[string]Provider),
		rotationInterval: defaultRotationInterval,
		cache:            make(map[string]*cacheEntry),
		refs:             make(map[string]SecretRef),
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Resolve fetches a secret using the appropriate provider. Results are cached
// and reused until expiry.
func (m *Manager) Resolve(ctx context.Context, ref SecretRef) (*Secret, error) {
	// Check cache first.
	m.mu.RLock()
	if entry, ok := m.cache[ref.Name]; ok {
		if !m.isExpired(entry) {
			m.mu.RUnlock()
			return entry.secret, nil
		}
	}
	m.mu.RUnlock()

	// Resolve from provider.
	secret, err := m.resolveFromProvider(ctx, ref)
	if err != nil {
		return nil, err
	}

	// Cache the result.
	m.mu.Lock()
	m.cache[ref.Name] = &cacheEntry{
		secret:     secret,
		resolvedAt: time.Now(),
	}
	m.refs[ref.Name] = ref
	m.mu.Unlock()

	return secret, nil
}

// ResolveAll resolves multiple secret references in batch. It returns a map
// of secret name to resolved secret. If any resolution fails, the entire
// batch fails.
func (m *Manager) ResolveAll(ctx context.Context, refs []SecretRef) (map[string]*Secret, error) {
	result := make(map[string]*Secret, len(refs))
	for _, ref := range refs {
		secret, err := m.Resolve(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("secrets: resolving %q: %w", ref.Name, err)
		}
		result[ref.Name] = secret
	}
	return result, nil
}

// InjectPath returns the container-side path where a named secret will be
// available (e.g., /run/secrets/my-token). Returns an error if the resolved
// path would escape the secrets base directory (path traversal attempt).
func (m *Manager) InjectPath(name string) (string, error) {
	resolved := path.Join(secretsBasePath, name)
	if !strings.HasPrefix(resolved, secretsBasePath+"/") && resolved != secretsBasePath {
		return "", fmt.Errorf("secrets: invalid secret name %q: path traversal detected", name)
	}
	return resolved, nil
}

// CachedSecrets returns a snapshot of all currently cached (resolved) secrets.
// This is used by the Sandbox runtime to build CredentialSources from resolved
// secret values rather than re-resolving them.
func (m *Manager) CachedSecrets() map[string]*Secret {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*Secret, len(m.cache))
	for name, entry := range m.cache {
		result[name] = entry.secret
	}
	return result
}

// StartRotation begins a background goroutine that periodically checks for
// expired secrets and re-resolves them. Call Close to stop rotation.
// If a rotation goroutine is already running, it is stopped and drained before
// the new one starts, preventing goroutine leaks from double-call.
func (m *Manager) StartRotation(ctx context.Context) error {
	// Stop any existing rotation goroutine before starting a new one.
	if m.cancel != nil {
		m.cancel()
		<-m.done
		m.cancel = nil
		m.done = nil
	}

	ctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.done = make(chan struct{})

	go m.rotationLoop(ctx)
	return nil
}

// Close stops the rotation goroutine (if running) and closes all registered
// providers.
func (m *Manager) Close() error {
	if m.cancel != nil {
		m.cancel()
		<-m.done
	}

	var errs []error
	for _, p := range m.providers {
		if err := p.Close(); err != nil {
			errs = append(errs, fmt.Errorf("secrets: closing provider %q: %w", p.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// resolveFromProvider looks up the named provider and calls Resolve.
func (m *Manager) resolveFromProvider(ctx context.Context, ref SecretRef) (*Secret, error) {
	p, ok := m.providers[ref.Provider]
	if !ok {
		return nil, fmt.Errorf("secrets: unknown provider %q", ref.Provider)
	}
	secret, err := p.Resolve(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("secrets: provider %q: %w", ref.Provider, err)
	}
	return secret, nil
}

// isExpired reports whether a cache entry has expired.
func (m *Manager) isExpired(entry *cacheEntry) bool {
	if entry.secret.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(entry.secret.ExpiresAt)
}

// rotationLoop periodically checks for expired secrets and re-resolves them.
func (m *Manager) rotationLoop(ctx context.Context) {
	defer close(m.done)

	ticker := time.NewTicker(m.rotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.rotateExpired(ctx)
		}
	}
}

// rotateExpired checks all cached secrets and re-resolves any that have expired.
func (m *Manager) rotateExpired(ctx context.Context) {
	m.mu.RLock()
	var expired []SecretRef
	for name, entry := range m.cache {
		if m.isExpired(entry) {
			if ref, ok := m.refs[name]; ok {
				expired = append(expired, ref)
			}
		}
	}
	m.mu.RUnlock()

	for _, ref := range expired {
		secret, err := m.resolveFromProvider(ctx, ref)
		if err != nil {
			// Log the error but continue rotating other secrets.
			continue
		}

		m.mu.Lock()
		m.cache[ref.Name] = &cacheEntry{
			secret:     secret,
			resolvedAt: time.Now(),
		}
		m.mu.Unlock()

		if m.onRotation != nil {
			m.onRotation(ref.Name, secret)
		}
	}
}
