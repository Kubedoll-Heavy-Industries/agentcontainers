package signing

import "context"

// fakeCmdRunner captures command invocations for testing.
type fakeCmdRunner struct {
	runFn func(ctx context.Context, name string, args []string, env []string) ([]byte, error)
}

func (f *fakeCmdRunner) Run(ctx context.Context, name string, args []string, env []string) ([]byte, error) {
	return f.runFn(ctx, name, args, env)
}
