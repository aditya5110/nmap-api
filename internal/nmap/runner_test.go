package nmap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNewRunnerDefaultsBinaryAndValidatesTimeout(t *testing.T) {
	runner, err := NewRunner("", time.Second)
	if err != nil {
		t.Fatalf("NewRunner returned error: %v", err)
	}
	if runner.binaryPath != "nmap" {
		t.Fatalf("expected default binary nmap, got %q", runner.binaryPath)
	}
	if _, err := NewRunner("nmap", 0); err == nil {
		t.Fatal("expected zero timeout to be rejected")
	}
}

func TestRunnerRunPassesArgumentsAndCapturesOutputSeparately(t *testing.T) {
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "args.txt")
	xml := `<nmaprun><host/></nmaprun>`
	script := fmt.Sprintf(
		"printf '%%s\\n' \"$@\" > %s\nprintf '%%s' %s\nprintf 'diagnostic text' >&2\n",
		shellQuote(argsPath),
		shellQuote(xml),
	)
	runner := newTestRunner(t, script, 5*time.Second)

	output, err := runner.Run(context.Background(), "scanme.example")
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if string(output.XML) != xml {
		t.Errorf("unexpected stdout XML: %q", output.XML)
	}
	if output.Stderr != "diagnostic text" {
		t.Errorf("unexpected stderr diagnostics: %q", output.Stderr)
	}

	argsData, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("read captured arguments: %v", err)
	}
	gotArgs := strings.Split(strings.TrimSuffix(string(argsData), "\n"), "\n")
	wantArgs := []string{"-Pn", "-T4", "-sT", "--top-ports", "1000", "-oX", "-", "scanme.example"}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("arguments = %q, want %q", gotArgs, wantArgs)
	}
}

func TestRunnerRunReportsExecutionFailure(t *testing.T) {
	runner := newTestRunner(t, "printf 'nmap diagnostic' >&2\nexit 7\n", time.Second)

	output, err := runner.Run(context.Background(), "scanme.example")
	if !errors.Is(err, ErrExecutionFailed) {
		t.Fatalf("expected execution failure, got %v", err)
	}
	var executionErr *ExecutionError
	if !errors.As(err, &executionErr) || executionErr.ExitCode == nil || *executionErr.ExitCode != 7 {
		t.Fatalf("expected exit code 7, got %#v", executionErr)
	}
	if output.Stderr != "nmap diagnostic" {
		t.Errorf("expected captured diagnostics, got %q", output.Stderr)
	}
}

func TestRunnerRunDistinguishesConfiguredTimeout(t *testing.T) {
	runner := newTestRunner(t, "exec /bin/sleep 5\n", 50*time.Millisecond)

	_, err := runner.Run(context.Background(), "scanme.example")
	if !errors.Is(err, ErrScanTimeout) {
		t.Fatalf("expected configured scan timeout, got %v", err)
	}
	if errors.Is(err, ErrParentDeadline) || errors.Is(err, ErrParentCanceled) {
		t.Fatalf("configured timeout was misclassified as parent context ending: %v", err)
	}
}

func TestRunnerRunWithTimeoutUsesPerScanTimeout(t *testing.T) {
	runner := newTestRunner(t, "exec /bin/sleep 5\n", 5*time.Second)

	_, err := runner.RunWithTimeout(context.Background(), "scanme.example", 50*time.Millisecond)
	if !errors.Is(err, ErrScanTimeout) {
		t.Fatalf("expected per-scan timeout, got %v", err)
	}
}

func TestRunnerRunDistinguishesParentCancellation(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "started")
	runner := newTestRunner(t, fmt.Sprintf(": > %s\nexec /bin/sleep 5\n", shellQuote(marker)), 5*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, err := runner.Run(ctx, "scanme.example")
		errCh <- err
	}()

	waitForMarkerAndCancel(t, marker, cancel, errCh)
}

func TestRunnerRunDistinguishesParentDeadline(t *testing.T) {
	runner := newTestRunner(t, "exec /bin/sleep 5\n", 5*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()

	_, err := runner.Run(ctx, "scanme.example")
	if !errors.Is(err, ErrParentDeadline) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected parent deadline error, got %v", err)
	}
	if errors.Is(err, ErrScanTimeout) {
		t.Fatalf("parent deadline was misclassified as configured scan timeout: %v", err)
	}
}

func TestRunnerRunRejectsEmptyTarget(t *testing.T) {
	runner := newTestRunner(t, "exit 0\n", time.Second)
	if _, err := runner.Run(context.Background(), ""); err == nil {
		t.Fatal("expected empty target to be rejected")
	}
}

func newTestRunner(t *testing.T, script string, timeout time.Duration) *Runner {
	t.Helper()
	binaryPath := filepath.Join(t.TempDir(), "fake-nmap")
	contents := "#!/bin/sh\nset -eu\n" + script
	if err := os.WriteFile(binaryPath, []byte(contents), 0o700); err != nil {
		t.Fatalf("write fake Nmap executable: %v", err)
	}
	runner, err := NewRunner(binaryPath, timeout)
	if err != nil {
		t.Fatalf("create runner: %v", err)
	}
	return runner
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func waitForMarkerAndCancel(t *testing.T, marker string, cancel context.CancelFunc, errCh <-chan error) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if _, err := os.Stat(marker); err == nil {
				cancel()
				select {
				case runErr := <-errCh:
					if !errors.Is(runErr, ErrParentCanceled) || !errors.Is(runErr, context.Canceled) {
						t.Fatalf("expected parent cancellation error, got %v", runErr)
					}
					if errors.Is(runErr, ErrScanTimeout) || errors.Is(runErr, ErrParentDeadline) {
						t.Fatalf("parent cancellation was misclassified: %v", runErr)
					}
					return
				case <-timer.C:
					t.Fatal("Nmap runner did not exit after parent cancellation")
				}
			}
		case runErr := <-errCh:
			t.Fatalf("Nmap runner exited before cancellation: %v", runErr)
		case <-timer.C:
			cancel()
			t.Fatal("fake Nmap executable did not start")
		}
	}
}
