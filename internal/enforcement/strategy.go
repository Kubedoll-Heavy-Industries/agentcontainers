// Package enforcement provides a strategy-based enforcement layer that selects
// the best available mechanism (gRPC sidecar) and applies container
// security policy through it. If no mechanism is available, enforcement fails closed.
package enforcement

import (
	"context"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/policy"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/secrets"
)

// Strategy applies and manages enforcement for a container.
type Strategy interface {
	// Apply attaches enforcement to a container. The initPID is the
	// container's PID 1 as seen from the host, used by the enforcer
	// to access /proc/<pid>/root/ for secret injection.
	Apply(ctx context.Context, containerID string, initPID uint32, p *policy.ContainerPolicy) error

	// Update modifies the enforcement policy for a running container.
	Update(ctx context.Context, containerID string, p *policy.ContainerPolicy) error

	// Remove detaches enforcement from a container.
	Remove(ctx context.Context, containerID string) error

	// InjectSecrets writes secret values into the container via the enforcer
	// sidecar. Called after Apply so that credential ACLs are active before
	// secrets are written. The enforcer is responsible for path validation and
	// access control.
	InjectSecrets(ctx context.Context, containerID string, resolved map[string]*secrets.Secret) error

	// Events returns an audit event channel, or nil if the strategy
	// doesn't support event streaming.
	Events(containerID string) <-chan Event

	// Level returns the enforcement level this strategy provides.
	Level() Level
}
