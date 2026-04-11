package enforcement

import (
	"context"
	"errors"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/policy"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/secrets"
)

// FailClosedStrategy refuses all enforcement operations when no mechanism
// is available. This ensures containers are not started without enforcement.
type FailClosedStrategy struct{}

// Apply returns an error because no enforcement mechanism is available.
func (s *FailClosedStrategy) Apply(_ context.Context, _ string, _ uint32, _ *policy.ContainerPolicy) error {
	return errors.New("enforcement: no enforcement mechanism available, refusing to start (fail-closed)")
}

// Update returns an error because no enforcement mechanism is available.
func (s *FailClosedStrategy) Update(_ context.Context, _ string, _ *policy.ContainerPolicy) error {
	return errors.New("enforcement: no enforcement mechanism available (fail-closed)")
}

// Remove is a no-op since no enforcement was applied.
func (s *FailClosedStrategy) Remove(_ context.Context, _ string) error {
	return nil
}

// InjectSecrets returns an error because no enforcement mechanism is available.
func (s *FailClosedStrategy) InjectSecrets(_ context.Context, _ string, _ map[string]*secrets.Secret) error {
	return errors.New("enforcement: not available: cannot inject secrets (fail-closed)")
}

// Events returns nil because there is no enforcement to emit events.
func (s *FailClosedStrategy) Events(_ string) <-chan Event {
	return nil
}

// Level returns LevelNone.
func (s *FailClosedStrategy) Level() Level {
	return LevelNone
}
