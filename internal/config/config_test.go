package config

import (
	"os"
	"reflect"
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

// TestLoadValidatesAndNormalizesScanAllowedTargets verifies valid mixed allowlist entries are trimmed/canonicalized and any invalid entry rejects the whole configuration.
func TestLoadValidatesAndNormalizesScanAllowedTargets(t *testing.T) {
	t.Run("valid entries are trimmed and normalized", func(t *testing.T) {
		setRequiredDatabaseConfig(t)
		t.Setenv("SCAN_ALLOWED_TARGETS", " 192.168.64.2 , Example.COM , 2001:0db8:0:0:0:0:0:1 ")

		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() returned error: %v", err)
		}
		want := []string{"192.168.64.2", "example.com", "2001:db8::1"}
		if !reflect.DeepEqual(cfg.ScanAllowedTargets, want) {
			t.Fatalf("ScanAllowedTargets = %#v, want %#v", cfg.ScanAllowedTargets, want)
		}
	})

	for _, entry := range []string{"192.168.64.999", "192.168.64.999.fas", "192.168.64.2.fas", "bad!hostname"} {
		t.Run("invalid "+entry, func(t *testing.T) {
			setRequiredDatabaseConfig(t)
			t.Setenv("SCAN_ALLOWED_TARGETS", "192.168.64.2,"+entry+",example.com")

			cfg, err := Load()
			if err == nil {
				t.Fatalf("Load() accepted invalid allowlist entry %q with config %#v", entry, cfg)
			}
			if !strings.Contains(err.Error(), "SCAN_ALLOWED_TARGETS") || !strings.Contains(err.Error(), entry) {
				t.Fatalf("Load() error %q should identify invalid allowlist entry %q", err, entry)
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
