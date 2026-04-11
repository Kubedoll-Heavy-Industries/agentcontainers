// Package policy translates agent capability declarations from configuration
// into concrete container security settings. It sits between the config layer
// and the container runtime, resolving declared capabilities into an
// enforceable ContainerPolicy.
package policy

// ContainerPolicy holds the resolved security settings derived from agent
// capability declarations. The container runtime consumes this to configure
// Linux namespaces, capabilities, mounts, and network isolation.
type ContainerPolicy struct {
	// CapDrop lists Linux capabilities to drop. Default: ["ALL"].
	CapDrop []string

	// CapAdd lists Linux capabilities to add. Only populated when
	// capabilities are explicitly granted by the agent configuration.
	CapAdd []string

	// SecurityOpt holds security options such as no-new-privileges and
	// seccomp profile paths.
	SecurityOpt []string

	// ReadonlyRootfs controls whether the container's root filesystem is
	// mounted read-only.
	ReadonlyRootfs bool

	// AllowedMounts describes the bind mounts the container is permitted.
	AllowedMounts []MountPolicy

	// NetworkMode controls the container's network namespace.
	// Valid values: "none" (isolated), "bridge" (outbound allowed).
	NetworkMode string

	// DNS lists DNS server addresses to configure when network access is
	// allowed.
	DNS []string

	// AllowedHosts lists hostnames the agent is permitted to reach when
	// network access is enabled. An empty list with NetworkMode "bridge"
	// means unrestricted outbound.
	AllowedHosts []string

	// AllowedEgressRules lists the original egress rules with host, port,
	// and protocol information. This supplements AllowedHosts with richer
	// detail needed for port-specific iptables enforcement.
	AllowedEgressRules []EgressPolicy

	// ShellAllowed indicates whether the agent may execute shell commands.
	ShellAllowed bool

	// AllowedCommands lists binaries the agent may invoke when shell access
	// is restricted to a specific set of commands.
	AllowedCommands []string

	// GitAllowed indicates whether the agent may perform git operations.
	GitAllowed bool

	// GitPushAllowed indicates whether the agent may push to remote
	// repositories.
	GitPushAllowed bool

	// GitPushBranches lists branch patterns the agent may push to.
	// An empty list with GitPushAllowed true means all branches are
	// permitted.
	GitPushBranches []string

	// GitDenyBranches lists branch patterns the agent must not push to.
	GitDenyBranches []string

	// SecretACLs defines per-secret access control rules for credential
	// enforcement. Each entry maps a secret path to the MCP tools allowed
	// to access it.
	SecretACLs []SecretACL
}

// EgressPolicy describes a permitted outbound connection with port and protocol
// details for fine-grained iptables enforcement.
type EgressPolicy struct {
	// Host is the hostname or IP address the agent may reach.
	Host string

	// Port is the destination port. Zero means any port.
	Port int

	// Protocol is the transport protocol ("tcp", "udp", "https", "http").
	// Empty or "https"/"http" are treated as "tcp" by the enforcement layer.
	Protocol string
}

// SecretACL defines which tools can access a specific secret.
type SecretACL struct {
	// Path is the secret file path (e.g., "/run/secrets/GITHUB_TOKEN").
	Path string

	// AllowedTools lists the MCP tool names permitted to read this secret.
	AllowedTools []string

	// TTLSeconds is the credential lifetime in seconds. 0 means no expiry.
	TTLSeconds uint64
}

// MountPolicy describes a permitted bind mount with access control.
type MountPolicy struct {
	// Source is the host path.
	Source string

	// Target is the in-container mount point.
	Target string

	// ReadOnly controls whether the mount is read-only.
	ReadOnly bool
}
