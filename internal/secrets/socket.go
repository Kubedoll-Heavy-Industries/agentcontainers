package secrets

import (
	"context"
	"net"
	"net/http"
	"time"
)

// unixSocketClient returns an http.Client that dials the given Unix domain
// socket for all requests. The Host header and URL authority are ignored by
// the transport; the caller should use "http://localhost" as the base URL.
// This allows providers to talk to agent sockets (Vault Agent, 1Password
// Connect) without putting tokens in the process environment.
func unixSocketClient(socketPath string) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}
}
