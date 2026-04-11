// Package approval implements interactive capability approval for agent sessions.
// It prompts users to approve or deny capability requests at runtime, tracking
// session approvals and persisting permanent approvals to the config file.
package approval

// Request represents a capability that needs user approval.
type Request struct {
	// Category is the capability type: "filesystem", "network", "shell", or "git".
	Category string

	// Action is a human-readable description of the capability, e.g. "read /home/user/project/**".
	Action string

	// Details provides additional context about why the capability is needed.
	Details string

	// Capability is the specific capability struct (FilesystemCaps, NetworkCaps, etc.).
	// The type depends on Category.
	Capability any

	// FullCmd is the complete command slice for shell requests, used to enforce
	// subcommand and denied-argument restrictions. Nil for non-shell requests.
	FullCmd []string
}

// Response represents the user's decision for a capability request.
type Response int

const (
	// Deny rejects the capability request.
	Deny Response = iota

	// AllowOnce permits the capability for this single operation only.
	AllowOnce

	// AllowSession permits the capability for the remainder of this session.
	AllowSession

	// AllowPersist permits the capability and saves it to the config file.
	AllowPersist
)

// String returns a human-readable name for the response.
func (r Response) String() string {
	switch r {
	case Deny:
		return "deny"
	case AllowOnce:
		return "allow-once"
	case AllowSession:
		return "allow-session"
	case AllowPersist:
		return "allow-persist"
	default:
		return "unknown"
	}
}

// Approver prompts for and collects approval decisions.
type Approver interface {
	// Prompt shows the request and returns the user's response.
	// It may return an error if the prompt fails (e.g., stdin closed).
	Prompt(req Request) (Response, error)
}
