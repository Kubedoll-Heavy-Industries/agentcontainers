package cli

import (
	"bytes"
	"testing"
	"time"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcerapi"
)

func TestNewAuditCmd_HasSubcommands(t *testing.T) {
	cmd := newAuditCmd()

	if cmd.Use != "audit" {
		t.Errorf("expected Use = %q, got %q", "audit", cmd.Use)
	}

	subs := cmd.Commands()
	names := make(map[string]bool)
	for _, sub := range subs {
		names[sub.Use] = true
	}

	for _, want := range []string{"events", "summary"} {
		if !names[want] {
			t.Errorf("expected subcommand %q, not found in %v", want, names)
		}
	}
}

func TestNewAuditEventsCmd_FlagDefaults(t *testing.T) {
	cmd := newAuditEventsCmd()

	tests := []struct {
		flag     string
		wantDef  string
		wantBool bool
		isBool   bool
	}{
		{flag: "addr", wantDef: defaultEnforcerAddr},
		{flag: "container", wantDef: ""},
		{flag: "type", wantDef: ""},
		{flag: "json", isBool: true, wantBool: false},
		{flag: "follow", isBool: true, wantBool: false},
	}

	for _, tt := range tests {
		t.Run(tt.flag, func(t *testing.T) {
			f := cmd.Flags().Lookup(tt.flag)
			if f == nil {
				t.Fatalf("flag %q not found", tt.flag)
			}
			if tt.isBool {
				if f.DefValue != "false" {
					t.Errorf("expected default %q, got %q", "false", f.DefValue)
				}
			} else {
				if f.DefValue != tt.wantDef {
					t.Errorf("expected default %q, got %q", tt.wantDef, f.DefValue)
				}
			}
		})
	}
}

func TestNewAuditEventsCmd_FollowShorthand(t *testing.T) {
	cmd := newAuditEventsCmd()
	f := cmd.Flags().Lookup("follow")
	if f == nil {
		t.Fatal("follow flag not found")
	}
	if f.Shorthand != "f" {
		t.Errorf("expected shorthand %q, got %q", "f", f.Shorthand)
	}
}

func TestNewAuditEventsCmd_CustomFlags(t *testing.T) {
	cmd := newAuditEventsCmd()

	err := cmd.Flags().Set("addr", "10.0.0.1:9999")
	if err != nil {
		t.Fatalf("setting addr flag: %v", err)
	}

	err = cmd.Flags().Set("container", "abc123")
	if err != nil {
		t.Fatalf("setting container flag: %v", err)
	}

	err = cmd.Flags().Set("type", "network")
	if err != nil {
		t.Fatalf("setting type flag: %v", err)
	}

	err = cmd.Flags().Set("json", "true")
	if err != nil {
		t.Fatalf("setting json flag: %v", err)
	}

	err = cmd.Flags().Set("follow", "true")
	if err != nil {
		t.Fatalf("setting follow flag: %v", err)
	}

	if v, _ := cmd.Flags().GetString("addr"); v != "10.0.0.1:9999" {
		t.Errorf("expected addr = %q, got %q", "10.0.0.1:9999", v)
	}
	if v, _ := cmd.Flags().GetString("container"); v != "abc123" {
		t.Errorf("expected container = %q, got %q", "abc123", v)
	}
	if v, _ := cmd.Flags().GetString("type"); v != "network" {
		t.Errorf("expected type = %q, got %q", "network", v)
	}
	if v, _ := cmd.Flags().GetBool("json"); !v {
		t.Error("expected json = true")
	}
	if v, _ := cmd.Flags().GetBool("follow"); !v {
		t.Error("expected follow = true")
	}
}

func TestNewAuditSummaryCmd_FlagDefaults(t *testing.T) {
	cmd := newAuditSummaryCmd()

	if cmd.Use != "summary" {
		t.Errorf("expected Use = %q, got %q", "summary", cmd.Use)
	}

	addrFlag := cmd.Flags().Lookup("addr")
	if addrFlag == nil {
		t.Fatal("addr flag not found")
	}
	if addrFlag.DefValue != defaultEnforcerAddr {
		t.Errorf("expected default %q, got %q", defaultEnforcerAddr, addrFlag.DefValue)
	}

	containerFlag := cmd.Flags().Lookup("container")
	if containerFlag == nil {
		t.Fatal("container flag not found")
	}
	if containerFlag.DefValue != "" {
		t.Errorf("expected default %q, got %q", "", containerFlag.DefValue)
	}
}

func TestAuditRegisteredInRoot(t *testing.T) {
	root := newRootCmd("test", "abc123", "2026-01-01")
	found := false
	for _, cmd := range root.Commands() {
		if cmd.Use == "audit" {
			found = true
			break
		}
	}
	if !found {
		t.Error("audit command not registered in root")
	}
}

func TestFormatTimestamp(t *testing.T) {
	tests := []struct {
		name string
		ns   uint64
		want string
	}{
		{name: "zero", ns: 0, want: "-"},
		{name: "epoch", ns: uint64(time.Date(2026, 1, 15, 10, 30, 45, 123000000, time.Local).UnixNano()), want: "10:30:45.123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatTimestamp(tt.ns)
			if got != tt.want {
				t.Errorf("formatTimestamp(%d) = %q, want %q", tt.ns, got, tt.want)
			}
		})
	}
}

func TestFormatDetails(t *testing.T) {
	tests := []struct {
		name    string
		details map[string]string
		want    string
	}{
		{name: "nil", details: nil, want: "-"},
		{name: "empty", details: map[string]string{}, want: "-"},
		{name: "single", details: map[string]string{"host": "example.com"}, want: "host=example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDetails(tt.details)
			if tt.name == "single" {
				// Single entry, deterministic.
				if got != tt.want {
					t.Errorf("formatDetails = %q, want %q", got, tt.want)
				}
			} else {
				if got != tt.want {
					t.Errorf("formatDetails = %q, want %q", got, tt.want)
				}
			}
		})
	}
}

func TestProtoEventToAuditEvent(t *testing.T) {
	ev := &enforcerapi.EnforcementEvent{
		TimestampNs: 1705312245123000000,
		ContainerId: "abc123def456",
		Domain:      "network",
		Verdict:     "block",
		Pid:         1234,
		Comm:        "curl",
		Details:     map[string]string{"host": "evil.com"},
	}

	ae := protoEventToAuditEvent(ev)

	if ae.ContainerID != "abc123def456" {
		t.Errorf("expected container_id = %q, got %q", "abc123def456", ae.ContainerID)
	}
	if ae.Domain != "network" {
		t.Errorf("expected domain = %q, got %q", "network", ae.Domain)
	}
	if ae.Verdict != "block" {
		t.Errorf("expected verdict = %q, got %q", "block", ae.Verdict)
	}
	if ae.PID != 1234 {
		t.Errorf("expected pid = %d, got %d", 1234, ae.PID)
	}
	if ae.Comm != "curl" {
		t.Errorf("expected comm = %q, got %q", "curl", ae.Comm)
	}
	if ae.Details["host"] != "evil.com" {
		t.Errorf("expected details[host] = %q, got %q", "evil.com", ae.Details["host"])
	}
}

func TestDisplayCollectedEvents_NoEvents(t *testing.T) {
	var buf bytes.Buffer
	err := displayCollectedEvents(nil, &buf, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.String() != "No enforcement events received.\n" {
		t.Errorf("unexpected output: %q", buf.String())
	}
}

func TestDisplayCollectedEvents_JSONEmpty(t *testing.T) {
	var buf bytes.Buffer
	err := displayCollectedEvents(nil, &buf, "", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should output an empty JSON array.
	if buf.String() != "[]\n" {
		t.Errorf("unexpected JSON output: %q", buf.String())
	}
}

func TestDisplayCollectedEvents_Table(t *testing.T) {
	events := []*enforcerapi.EnforcementEvent{
		{
			TimestampNs: 1705312245123000000,
			ContainerId: "abc123def456789",
			Domain:      "network",
			Verdict:     "allow",
			Pid:         42,
			Comm:        "node",
		},
	}

	var buf bytes.Buffer
	err := displayCollectedEvents(events, &buf, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	// Verify the header is present.
	if !bytes.Contains([]byte(output), []byte("TIMESTAMP")) {
		t.Error("expected TIMESTAMP header in output")
	}
	if !bytes.Contains([]byte(output), []byte("network")) {
		t.Error("expected 'network' in output")
	}
	if !bytes.Contains([]byte(output), []byte("allow")) {
		t.Error("expected 'allow' in output")
	}
	if !bytes.Contains([]byte(output), []byte("abc123def456")) {
		t.Error("expected truncated container ID in output")
	}
}
