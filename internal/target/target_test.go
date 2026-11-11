package target

import (
	"strings"
	"testing"
)

// TestNormalizeValidTargets verifies valid IPv4, IPv6, and hostnames are accepted and normalized without DNS lookup.
func TestNormalizeValidTargets(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		want     string
		wantType string
	}{
		{name: "private IPv4", input: "192.168.64.2", want: "192.168.64.2", wantType: TypeIP},
		{name: "IPv4", input: "10.0.0.1", want: "10.0.0.1", wantType: TypeIP},
		{name: "public IPv4", input: "8.8.8.8", want: "8.8.8.8", wantType: TypeIP},
		{name: "IPv6", input: "2001:0db8:0:0:0:0:0:1", want: "2001:db8::1", wantType: TypeIP},
		{name: "uppercase hostname", input: "ExAmPle.COM.", want: "example.com", wantType: TypeHostname},
		{name: "numeric DNS label", input: "123.456.789.example", want: "123.456.789.example", wantType: TypeHostname},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotType, err := Normalize(test.input)
			if err != nil {
				t.Fatalf("Normalize(%q) returned error: %v", test.input, err)
			}
			if got != test.want || gotType != test.wantType {
				t.Fatalf("Normalize(%q) = (%q, %q), want (%q, %q)", test.input, got, gotType, test.want, test.wantType)
			}
		})
	}
}

// TestNormalizeRejectsMalformedIPAndHostnameTargets verifies invalid IP literals and invalid DNS label formats cannot pass as hostnames.
func TestNormalizeRejectsMalformedIPAndHostnameTargets(t *testing.T) {
	invalid := []string{
		"192.168.64.999",
		"192.168.64.999.fas",
		"192.168.64.2.fas",
		"192.168.1",
		"192.168.1.1.1",
		"256.1.1.1",
		"192.168.1.-1",
		"2001:db8:::1",
		"2001:db8:xyz::1",
		"bad!hostname",
		"host..example",
		"-host.example",
		"host-.example",
		"toolong." + strings.Repeat("a", 64),
		strings.Repeat("a", 64) + ".example",
		strings.Join([]string{strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 63)}, "."),
	}
	for _, input := range invalid {
		t.Run(input, func(t *testing.T) {
			if normalized, targetType, err := Normalize(input); err == nil {
				t.Fatalf("Normalize(%q) = (%q, %q), want validation error", input, normalized, targetType)
			}
		})
	}
}
