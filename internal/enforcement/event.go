package enforcement

// Event represents an enforcement audit event.
type Event struct {
	Timestamp uint64
	PID       uint32
	UID       uint32
	Type      EventType
	Verdict   Verdict
	Comm      string
	// Domain-specific data
	Net  *NetEvent
	FS   *FSEvent
	Exec *ExecEvent
}

// EventType identifies the kind of enforcement audit event.
type EventType uint32

const (
	EventNetConnect  EventType = 1
	EventNetSendmsg  EventType = 2
	EventNetBind     EventType = 3
	EventFSOpen      EventType = 4
	EventExec        EventType = 5
	EventCred        EventType = 6
	EventDNSResponse EventType = 7
)

// Verdict indicates whether an enforcement hook allowed or blocked the operation.
type Verdict uint32

const (
	VerdictBlock Verdict = 0
	VerdictAllow Verdict = 1
)

// NetEvent holds network-specific event data.
type NetEvent struct {
	DstIP4    uint32
	DstIP6    [4]uint32
	DstPort   uint16
	Protocol  uint8
	IPVersion uint8
}

// FSEvent holds filesystem-specific event data.
type FSEvent struct {
	Path  string
	Flags uint32
}

// ExecEvent holds process execution event data.
type ExecEvent struct {
	Binary string
}
