package nmap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

var (
	ErrScanTimeout     = errors.New("nmap scan timed out")
	ErrParentCanceled  = errors.New("nmap scan canceled by parent context")
	ErrParentDeadline  = errors.New("parent context deadline exceeded")
	ErrExecutionFailed = errors.New("nmap execution failed")
)

// Runner executes the approved Nmap scan profile for one target.
type Runner struct {
	binaryPath string
	timeout    time.Duration
}

// RunOutput keeps Nmap XML and stderr diagnostics separate, including on failure.
type RunOutput struct {
	XML    []byte
	Stderr string
}

// ExecutionError represents an Nmap process failure without exposing internal process details.
type ExecutionError struct {
	ExitCode *int
}

func (e *ExecutionError) Error() string {
	if e.ExitCode != nil {
		return fmt.Sprintf("nmap exited with status %d", *e.ExitCode)
	}
	return "unable to start nmap"
}

func (e *ExecutionError) Unwrap() error {
	return ErrExecutionFailed
}

// NewRunner uses nmap when binaryPath is empty and requires a positive per-scan timeout.
func NewRunner(binaryPath string, timeout time.Duration) (*Runner, error) {
	if timeout <= 0 {
		return nil, errors.New("nmap timeout must be greater than zero")
	}
	if binaryPath == "" {
		binaryPath = "nmap"
	}

	return &Runner{binaryPath: binaryPath, timeout: timeout}, nil
}

// Run invokes Nmap with explicit arguments and a timeout derived from the parent context.
func (r *Runner) Run(ctx context.Context, target string) (RunOutput, error) {
	if r == nil {
		return RunOutput{}, errors.New("nmap runner is not configured")
	}
	return r.RunWithTimeout(ctx, target, r.timeout)
}

// RunWithTimeout invokes Nmap using a timeout specific to this scan.
func (r *Runner) RunWithTimeout(ctx context.Context, target string, timeout time.Duration) (RunOutput, error) {
	if r == nil {
		return RunOutput{}, errors.New("nmap runner is not configured")
	}
	if ctx == nil {
		return RunOutput{}, errors.New("nmap context must not be nil")
	}
	if target == "" {
		return RunOutput{}, errors.New("nmap target must not be empty")
	}
	if timeout <= 0 {
		return RunOutput{}, errors.New("nmap timeout must be greater than zero")
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{
		"-Pn",
		"-T4",
		"-sT",
		"--top-ports", "1000",
		"-oX", "-",
		target,
	}
	cmd := exec.CommandContext(scanCtx, r.binaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := RunOutput{XML: stdout.Bytes(), Stderr: stderr.String()}
	if err == nil {
		return output, nil
	}

	if parentErr := ctx.Err(); parentErr != nil {
		if errors.Is(parentErr, context.Canceled) {
			return output, fmt.Errorf("%w: %w", ErrParentCanceled, parentErr)
		}
		if errors.Is(parentErr, context.DeadlineExceeded) {
			return output, fmt.Errorf("%w: %w", ErrParentDeadline, parentErr)
		}
	}
	if errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
		return output, ErrScanTimeout
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		exitCode := exitErr.ExitCode()
		return output, &ExecutionError{ExitCode: &exitCode}
	}
	return output, &ExecutionError{}
}
