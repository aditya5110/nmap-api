package config

import (
	"os"
	"strings"
	"testing"
)

// TestLoadRejectsEmptyScanAllowedTargetsEntries verifies leading, trailing, or repeated commas make SCAN_ALLOWED_TARGETS invalid.
func TestLoadRejectsEmptyScanAllowedTargetsEntries(t *testing.T) {
	values := []string{
		",127.0.0.1",
		"127.0.0.1,",
		"127.0.0.1,,::1",
		"127.0.0.1, ,::1",
	}
	for _, value := range values {
		t.Run(value, func(t *testing.T) {
			setRequiredDatabaseConfig(t)
			t.Setenv("SCAN_ALLOWED_TARGETS", value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SCAN_ALLOWED_TARGETS") {
				t.Fatalf("Load() error = %v, want SCAN_ALLOWED_TARGETS configuration error", err)
			}
		})
	}
}

// TestLoadAllowsEmptyOrUnsetScanAllowedTargets verifies an empty or unset allowlist loads with no entries, enabling default-deny scans.
func TestLoadAllowsEmptyOrUnsetScanAllowedTargets(t *testing.T) {
	tests := []struct {
		name  string
		unset bool
	}{
		{name: "empty"},
		{name: "unset", unset: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setRequiredDatabaseConfig(t)
			t.Setenv("SCAN_ALLOWED_TARGETS", "127.0.0.1")
			if test.unset {
				if err := os.Unsetenv("SCAN_ALLOWED_TARGETS"); err != nil {
					t.Fatalf("unset allowlist: %v", err)
				}
			} else {
				t.Setenv("SCAN_ALLOWED_TARGETS", "")
			}

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() returned error: %v", err)
			}
			if len(cfg.ScanAllowedTargets) != 0 {
				t.Fatalf("expected empty allowlist, got %#v", cfg.ScanAllowedTargets)
			}
		})
	}
}

func setRequiredDatabaseConfig(t *testing.T) {
	t.Helper()
	t.Setenv("DB_HOST", "localhost")
	t.Setenv("DB_USER", "test-user")
	t.Setenv("DB_PASSWORD", "test-password")
	t.Setenv("DB_NAME", "test-db")
}
