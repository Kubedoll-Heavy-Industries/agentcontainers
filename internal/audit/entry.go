package audit

import "time"

// EventType categorizes audit events.
type EventType string

const (
	EventExec        EventType = "exec"
	EventApproval    EventType = "approval"
	EventEscalation  EventType = "escalation"
	EventEnforcement EventType = "enforcement"
	EventSecret      EventType = "secret"
	EventLifecycle   EventType = "lifecycle"
)

// Actor identifies who triggered an event.
type Actor struct {
	Type string `json:"type"` // "agent", "tool", "user", "system"
	Name string `json:"name"` // tool name, agent ID, "human", etc.
}

// Verdict is the outcome of a policy decision.
type Verdict string

const (
	VerdictAllow  Verdict = "allow"
	VerdictDeny   Verdict = "deny"
	VerdictPrompt Verdict = "prompt"
)

// Entry is a single audit log record.
type Entry struct {
	Timestamp time.Time         `json:"timestamp"`
	SessionID string            `json:"sessionId"`
	Sequence  uint64            `json:"sequence"`
	EventType EventType         `json:"eventType"`
	Actor     Actor             `json:"actor"`
	Verdict   Verdict           `json:"verdict,omitempty"`
	Command   string            `json:"command,omitempty"`
	Resource  string            `json:"resource,omitempty"`
	Detail    string            `json:"detail,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	PrevHash  string            `json:"prevHash"`
	EntryHash string            `json:"entryHash"`
}
