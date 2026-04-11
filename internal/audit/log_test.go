package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestNewLogger(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLogger("test-session", WithDir(dir))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close() //nolint:errcheck

	path := l.Path()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("log file not created at %s: %v", path, err)
	}

	if !strings.HasSuffix(path, "test-session.jsonl") {
		t.Errorf("expected path to end with test-session.jsonl, got %s", path)
	}
}

func TestLogEntry(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLogger("log-entry-test", WithDir(dir))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	actor := Actor{Type: "agent", Name: "claude"}
	err = l.Log(EventExec, actor,
		WithVerdict(VerdictAllow),
		WithCommand("ls -la"),
		WithResource("/home/user"),
		WithDetail("listing directory"),
		WithMetadata("cwd", "/home/user"),
	)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	_ = l.Close()

	entries, err := ReadLog(l.Path())
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	e := entries[0]
	if e.SessionID != "log-entry-test" {
		t.Errorf("sessionID = %q, want %q", e.SessionID, "log-entry-test")
	}
	if e.Sequence != 0 {
		t.Errorf("sequence = %d, want 0", e.Sequence)
	}
	if e.EventType != EventExec {
		t.Errorf("eventType = %q, want %q", e.EventType, EventExec)
	}
	if e.Actor.Type != "agent" || e.Actor.Name != "claude" {
		t.Errorf("actor = %+v, want {Type:agent Name:claude}", e.Actor)
	}
	if e.Verdict != VerdictAllow {
		t.Errorf("verdict = %q, want %q", e.Verdict, VerdictAllow)
	}
	if e.Command != "ls -la" {
		t.Errorf("command = %q, want %q", e.Command, "ls -la")
	}
	if e.Resource != "/home/user" {
		t.Errorf("resource = %q, want %q", e.Resource, "/home/user")
	}
	if e.Detail != "listing directory" {
		t.Errorf("detail = %q, want %q", e.Detail, "listing directory")
	}
	if e.Metadata["cwd"] != "/home/user" {
		t.Errorf("metadata[cwd] = %q, want %q", e.Metadata["cwd"], "/home/user")
	}
	if e.PrevHash != zeroHash {
		t.Errorf("prevHash = %q, want zero hash", e.PrevHash)
	}
	if e.EntryHash == "" {
		t.Error("entryHash is empty")
	}
}

func TestLogMultipleEntries(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLogger("multi-test", WithDir(dir))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	actor := Actor{Type: "tool", Name: "bash"}
	for i := 0; i < 3; i++ {
		if err := l.Log(EventExec, actor, WithCommand("echo hello")); err != nil {
			t.Fatalf("Log entry %d: %v", i, err)
		}
	}
	_ = l.Close()

	entries, err := ReadLog(l.Path())
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	for i, e := range entries {
		if e.Sequence != uint64(i) {
			t.Errorf("entry %d: sequence = %d, want %d", i, e.Sequence, i)
		}
	}
}

func TestHashChain(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLogger("chain-test", WithDir(dir))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	actor := Actor{Type: "system", Name: "enforcer"}
	for i := 0; i < 5; i++ {
		if err := l.Log(EventEnforcement, actor, WithVerdict(VerdictDeny)); err != nil {
			t.Fatalf("Log entry %d: %v", i, err)
		}
	}
	_ = l.Close()

	entries, err := ReadLog(l.Path())
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}

	if err := ValidateChain(entries); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
}

func TestHashChainTampered(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLogger("tamper-test", WithDir(dir))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	actor := Actor{Type: "agent", Name: "codex"}
	for i := 0; i < 3; i++ {
		if err := l.Log(EventExec, actor, WithCommand("cmd")); err != nil {
			t.Fatalf("Log entry %d: %v", i, err)
		}
	}
	_ = l.Close()

	entries, err := ReadLog(l.Path())
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}

	// Tamper with entry 1's command field.
	entries[1].Command = "rm -rf /"

	err = ValidateChain(entries)
	if err == nil {
		t.Fatal("expected ValidateChain to fail on tampered entry")
	}
	if !strings.Contains(err.Error(), "entry 1") {
		t.Errorf("expected error about entry 1, got: %v", err)
	}
}

func TestReadLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manual.jsonl")

	entry := Entry{
		SessionID: "manual",
		Sequence:  0,
		EventType: EventLifecycle,
		Actor:     Actor{Type: "system", Name: "init"},
		PrevHash:  zeroHash,
	}
	entry.EntryHash = computeHash(entry)

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	entries, err := ReadLog(path)
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].SessionID != "manual" {
		t.Errorf("sessionID = %q, want %q", entries[0].SessionID, "manual")
	}
	if entries[0].EventType != EventLifecycle {
		t.Errorf("eventType = %q, want %q", entries[0].EventType, EventLifecycle)
	}
}

func TestValidateChainEmpty(t *testing.T) {
	if err := ValidateChain(nil); err != nil {
		t.Errorf("ValidateChain(nil) = %v, want nil", err)
	}
	if err := ValidateChain([]Entry{}); err != nil {
		t.Errorf("ValidateChain([]) = %v, want nil", err)
	}
}

func TestLogConcurrent(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLogger("concurrent-test", WithDir(dir))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	const numGoroutines = 10
	const entriesPerGoroutine = 5

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	for g := 0; g < numGoroutines; g++ {
		go func() {
			defer wg.Done()
			actor := Actor{Type: "agent", Name: "worker"}
			for i := 0; i < entriesPerGoroutine; i++ {
				if err := l.Log(EventExec, actor, WithCommand("work")); err != nil {
					t.Errorf("Log: %v", err)
				}
			}
		}()
	}
	wg.Wait()
	_ = l.Close()

	entries, err := ReadLog(l.Path())
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}

	expectedCount := numGoroutines * entriesPerGoroutine
	if len(entries) != expectedCount {
		t.Fatalf("expected %d entries, got %d", expectedCount, len(entries))
	}

	// Chain should still be valid because the mutex serializes writes.
	if err := ValidateChain(entries); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
}

func TestLoggerClose(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLogger("close-test", WithDir(dir))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Subsequent Log should return error.
	actor := Actor{Type: "agent", Name: "claude"}
	err = l.Log(EventExec, actor)
	if err == nil {
		t.Fatal("expected error after Close, got nil")
	}
	if !strings.Contains(err.Error(), "closed") {
		t.Errorf("expected error about closed logger, got: %v", err)
	}

	// Double close should not error.
	if err := l.Close(); err != nil {
		t.Errorf("double Close: %v", err)
	}
}

func TestListLogs(t *testing.T) {
	dir := t.TempDir()

	// Create a couple of log files.
	for _, name := range []string{"session-a.jsonl", "session-b.jsonl", "not-a-log.txt"} {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("creating %s: %v", name, err)
		}
		_ = f.Close()
	}

	logs, err := ListLogs(dir)
	if err != nil {
		t.Fatalf("ListLogs: %v", err)
	}
	if len(logs) != 2 {
		t.Fatalf("expected 2 logs, got %d: %v", len(logs), logs)
	}
}

func TestListLogsEmpty(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nonexistent")
	logs, err := ListLogs(dir)
	if err != nil {
		t.Fatalf("ListLogs: %v", err)
	}
	if len(logs) != 0 {
		t.Errorf("expected 0 logs, got %d", len(logs))
	}
}
