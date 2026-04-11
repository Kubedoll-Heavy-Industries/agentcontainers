//go:build !darwin

package container

func probeSandboxSocket() bool {
	return false
}
