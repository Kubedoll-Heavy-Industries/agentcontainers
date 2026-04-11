//go:build darwin

package container

import (
	"os"
	"path/filepath"
)

func probeSandboxSocket() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	// Docker Desktop for Mac creates the sandbox socket at this path.
	socketPath := filepath.Join(home, ".docker", "sandboxes", "sandboxd.sock")
	_, err = os.Stat(socketPath)
	return err == nil
}
