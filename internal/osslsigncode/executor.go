package osslsigncode

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
)

const (
	osslsigncodeCommand = "osslsigncode"
)

// ExecutorIface is the interface that wraps the Sign operation.
// It allows the service to be tested with a mock executor.
type ExecutorIface interface {
	Sign(ctx context.Context, opts SignOptions, extraFiles []*os.File) (Result, error)
}

type Executor struct {
	Command string
	logger  *slog.Logger
}

func New() *Executor {
	return &Executor{
		Command: osslsigncodeCommand,
		logger:  slog.Default(),
	}
}

func (e *Executor) SetCommand(command string) {
	e.Command = command
}

func (e *Executor) run(ctx context.Context, command string, params osslsigncodeParams, extraFiles []*os.File) (Result, error) {
	var stdout, stderr bytes.Buffer
	args := params.Args()
	e.logger.Debug("executor.run", "command", command, "args", args, "extraFiles", len(extraFiles))
	cmd := exec.CommandContext(ctx, e.Command, append([]string{command}, args...)...)
	cmd.ExtraFiles = extraFiles
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	result := Result{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}
	e.logger.Debug("executor.run result", "err", err, "stdout", result.Stdout, "stderr", result.Stderr)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			e.logger.Debug("executor.run exit code", "exitCode", exitErr.ExitCode())
			err = &Error{
				ExitCode: exitErr.ExitCode(),
				Result:   result,
			}
		}
		return Result{}, err
	}
	return result, nil
}

func (e *Executor) Sign(ctx context.Context, opts SignOptions, extraFiles []*os.File) (Result, error) {
	// If password is provided, create a pipe and pass as extra file
	if opts.Password != "" {
		r, w, err := os.Pipe()
		if err != nil {
			return Result{}, err
		}

		// Write password to pipe in a goroutine
		go func() {
			defer func() { _ = w.Close() }()
			_, _ = w.Write([]byte(opts.Password))
		}()

		// Add pipe to extra files (fd 3)
		extraFiles = append(extraFiles, r)
		opts.Password = "" // Clear the password from options after reading from pipe
	}

	// Debug: print arguments
	args := opts.Args()
	e.logger.Debug("osslsigncode sign", "args", args)

	return e.run(ctx, "sign", args, extraFiles)
}
