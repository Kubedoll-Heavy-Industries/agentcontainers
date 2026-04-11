package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Logger provides append-only audit logging with hash chain integrity.
type Logger struct {
	mu        sync.Mutex
	file      *os.File
	dir       string
	sessionID string
	sequence  uint64
	prevHash  string
	closed    bool
}

// LoggerOption configures a Logger.
type LoggerOption func(*Logger)

// WithDir sets the base audit directory (default: ~/.ac/audit/).
func WithDir(dir string) LoggerOption {
	return func(l *Logger) {
		l.dir = dir
	}
}

// NewLogger creates a new audit logger for the given session.
func NewLogger(sessionID string, opts ...LoggerOption) (*Logger, error) {
	l := &Logger{
		sessionID: sessionID,
		prevHash:  zeroHash,
	}

	for _, opt := range opts {
		opt(l)
	}

	if l.dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("audit: resolving home directory: %w", err)
		}
		l.dir = filepath.Join(home, ".ac", "audit")
	}

	if err := os.MkdirAll(l.dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: creating directory %s: %w", l.dir, err)
	}

	path := filepath.Join(l.dir, sessionID+".jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: opening log file: %w", err)
	}
	l.file = f

	return l, nil
}

// LogEntryOption configures optional fields on an audit entry.
type LogEntryOption func(*Entry)

// WithVerdict sets the verdict on an entry.
func WithVerdict(v Verdict) LogEntryOption {
	return func(e *Entry) { e.Verdict = v }
}

// WithCommand sets the command on an entry.
func WithCommand(cmd string) LogEntryOption {
	return func(e *Entry) { e.Command = cmd }
}

// WithResource sets the resource on an entry.
func WithResource(res string) LogEntryOption {
	return func(e *Entry) { e.Resource = res }
}

// WithDetail sets the detail on an entry.
func WithDetail(detail string) LogEntryOption {
	return func(e *Entry) { e.Detail = detail }
}

// WithMetadata adds a key-value pair to the entry metadata.
func WithMetadata(key, value string) LogEntryOption {
	return func(e *Entry) {
		if e.Metadata == nil {
			e.Metadata = make(map[string]string)
		}
		e.Metadata[key] = value
	}
}

// Log appends an entry to the audit log.
func (l *Logger) Log(eventType EventType, actor Actor, opts ...LogEntryOption) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return errors.New("audit: logger is closed")
	}

	entry := Entry{
		Timestamp: time.Now().UTC(),
		SessionID: l.sessionID,
		Sequence:  l.sequence,
		EventType: eventType,
		Actor:     actor,
		PrevHash:  l.prevHash,
	}

	for _, opt := range opts {
		opt(&entry)
	}

	entry.EntryHash = computeHash(entry)

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: marshalling entry: %w", err)
	}

	data = append(data, '\n')
	if _, err := l.file.Write(data); err != nil {
		return fmt.Errorf("audit: writing entry: %w", err)
	}

	l.prevHash = entry.EntryHash
	l.sequence++

	return nil
}

// Close flushes and closes the log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}

	l.closed = true
	return l.file.Close()
}

// Path returns the log file path.
func (l *Logger) Path() string {
	return filepath.Join(l.dir, l.sessionID+".jsonl")
}

// computeHash computes the SHA-256 hash for an entry using the chain fields.
func computeHash(e Entry) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s|%s|%s|%d|%s|%s:%s|%s|%s",
		e.PrevHash,
		e.Timestamp.Format(time.RFC3339Nano),
		e.SessionID,
		e.Sequence,
		e.EventType,
		e.Actor.Type, e.Actor.Name,
		e.Verdict,
		e.Command,
	)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// ReadLog reads a JSONL audit log file and returns all entries.
func ReadLog(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("audit: opening log file: %w", err)
	}
	defer f.Close() //nolint:errcheck

	var entries []Entry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("audit: parsing entry: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("audit: reading log: %w", err)
	}

	return entries, nil
}

// ValidateChain verifies the hash chain integrity of a sequence of entries.
// Returns an error describing the first broken link, or nil if the chain is valid.
func ValidateChain(entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}

	for i, entry := range entries {
		// Verify prevHash links.
		if i == 0 {
			if entry.PrevHash != zeroHash {
				return fmt.Errorf("audit: entry 0: expected prevHash %s, got %s", zeroHash, entry.PrevHash)
			}
		} else {
			if entry.PrevHash != entries[i-1].EntryHash {
				return fmt.Errorf("audit: entry %d: prevHash mismatch: expected %s, got %s", i, entries[i-1].EntryHash, entry.PrevHash)
			}
		}

		// Verify the entry's own hash.
		expected := computeHash(entry)
		if entry.EntryHash != expected {
			return fmt.Errorf("audit: entry %d: hash mismatch: expected %s, got %s", i, expected, entry.EntryHash)
		}

		// Verify sequence is correct.
		if entry.Sequence != uint64(i) {
			return fmt.Errorf("audit: entry %d: expected sequence %d, got %d", i, i, entry.Sequence)
		}
	}

	return nil
}

// ListLogs returns all session audit log files in the audit directory.
// Each returned path is relative to the audit directory.
func ListLogs(dir string) ([]string, error) {
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("audit: resolving home directory: %w", err)
		}
		dir = filepath.Join(home, ".ac", "audit")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: reading directory: %w", err)
	}

	var logs []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".jsonl" {
			logs = append(logs, e.Name())
		}
	}
	return logs, nil
}
