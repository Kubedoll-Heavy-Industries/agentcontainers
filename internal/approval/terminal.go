package approval

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// Compile-time check that TerminalApprover implements Approver.
var _ Approver = (*TerminalApprover)(nil)

// TerminalApprover prompts for capability approvals via a terminal interface.
type TerminalApprover struct {
	in             io.Reader
	out            io.Writer
	nonInteractive bool
}

// TerminalOption configures a TerminalApprover.
type TerminalOption func(*terminalOptions)

// terminalOptions holds the configuration for a TerminalApprover.
type terminalOptions struct {
	in             io.Reader
	out            io.Writer
	nonInteractive bool
}

// defaultTerminalOptions returns sensible defaults for terminal approval.
func defaultTerminalOptions() *terminalOptions {
	return &terminalOptions{
		in:             os.Stdin,
		out:            os.Stdout,
		nonInteractive: false,
	}
}

// WithInput sets the input reader for the terminal approver.
// This is useful for testing or reading from alternative input sources.
func WithInput(r io.Reader) TerminalOption {
	return func(o *terminalOptions) {
		if r != nil {
			o.in = r
		}
	}
}

// WithOutput sets the output writer for the terminal approver.
// This is useful for testing or writing to alternative output destinations.
func WithOutput(w io.Writer) TerminalOption {
	return func(o *terminalOptions) {
		if w != nil {
			o.out = w
		}
	}
}

// WithNonInteractive sets the approver to non-interactive mode.
// In this mode, all capability requests are automatically denied.
// This is useful for CI/CD environments or headless operation.
func WithNonInteractive(enabled bool) TerminalOption {
	return func(o *terminalOptions) {
		o.nonInteractive = enabled
	}
}

// NewTerminalApprover creates a new terminal-based Approver.
func NewTerminalApprover(opts ...TerminalOption) *TerminalApprover {
	o := defaultTerminalOptions()
	for _, opt := range opts {
		opt(o)
	}

	return &TerminalApprover{
		in:             o.in,
		out:            o.out,
		nonInteractive: o.nonInteractive,
	}
}

// Prompt displays the capability request and waits for user input.
// In non-interactive mode, it automatically returns Deny.
func (t *TerminalApprover) Prompt(req Request) (Response, error) {
	if t.nonInteractive {
		_, _ = fmt.Fprintf(t.out, "Capability request auto-denied (non-interactive mode): %s - %s\n", req.Category, req.Action)
		return Deny, nil
	}

	// Display the capability request.
	t.displayRequest(req)

	// Read and process user input.
	scanner := bufio.NewScanner(t.in)
	for {
		_, _ = fmt.Fprintf(t.out, "Choice [d/o/s/p]: ")

		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return Deny, fmt.Errorf("reading input: %w", err)
			}
			// EOF reached without valid input; treat as deny.
			_, _ = fmt.Fprintf(t.out, "\nInput closed, denying request.\n")
			return Deny, nil
		}

		input := strings.TrimSpace(strings.ToLower(scanner.Text()))
		switch input {
		case "d", "deny":
			return Deny, nil
		case "o", "once":
			return AllowOnce, nil
		case "s", "session":
			return AllowSession, nil
		case "p", "persist":
			return AllowPersist, nil
		default:
			_, _ = fmt.Fprintf(t.out, "Invalid choice %q. Please enter d, o, s, or p.\n", input)
		}
	}
}

// displayRequest formats and prints the capability request to the output.
func (t *TerminalApprover) displayRequest(req Request) {
	_, _ = fmt.Fprintf(t.out, "\n")
	_, _ = fmt.Fprintf(t.out, "========================================\n")
	_, _ = fmt.Fprintf(t.out, "        Capability Request\n")
	_, _ = fmt.Fprintf(t.out, "========================================\n")
	_, _ = fmt.Fprintf(t.out, "\n")
	_, _ = fmt.Fprintf(t.out, "Category: %s\n", req.Category)
	_, _ = fmt.Fprintf(t.out, "Action:   %s\n", req.Action)

	if req.Details != "" {
		_, _ = fmt.Fprintf(t.out, "\n")
		_, _ = fmt.Fprintf(t.out, "Details:\n")
		_, _ = fmt.Fprintf(t.out, "  %s\n", req.Details)
	}

	_, _ = fmt.Fprintf(t.out, "\n")
	_, _ = fmt.Fprintf(t.out, "The agent is requesting access not in the current capability set.\n")
	_, _ = fmt.Fprintf(t.out, "\n")
	_, _ = fmt.Fprintf(t.out, "[d] Deny\n")
	_, _ = fmt.Fprintf(t.out, "[o] Allow once\n")
	_, _ = fmt.Fprintf(t.out, "[s] Allow for this session\n")
	_, _ = fmt.Fprintf(t.out, "[p] Allow and persist to config\n")
	_, _ = fmt.Fprintf(t.out, "\n")
}
