// Package target validates and normalizes scan IP addresses and DNS hostnames.
package target

import (
	"fmt"
	"net/netip"
	"strings"
)

const (
	TypeIP       = "ip"
	TypeHostname = "hostname"
)

// Normalize validates an IPv4 address, IPv6 address, or DNS hostname and returns
// its canonical comparison form and target type. It performs no DNS lookup.
func Normalize(value string) (normalized, targetType string, err error) {
	if value == "" || strings.TrimSpace(value) != value {
		return "", "", fmt.Errorf("target must be non-empty and must not contain surrounding whitespace")
	}

	if address, parseErr := netip.ParseAddr(value); parseErr == nil {
		if address.Zone() != "" {
			return "", "", fmt.Errorf("IPv6 zone identifiers are not supported")
		}
		address = address.Unmap()
		return address.String(), TypeIP, nil
	}
	if looksLikeMalformedIPAddress(value) {
		return "", "", fmt.Errorf("malformed IP address")
	}

	hostname := strings.TrimSuffix(strings.ToLower(value), ".")
	if len(hostname) == 0 || len(hostname) > 253 {
		return "", "", fmt.Errorf("hostname length is invalid")
	}
	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", "", fmt.Errorf("hostname label is invalid")
		}
		for _, character := range label {
			if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-') {
				return "", "", fmt.Errorf("hostname contains an invalid character")
			}
		}
	}
	if hasIPv4NumericPrefix(labels) {
		return "", "", fmt.Errorf("malformed IP-like target")
	}
	return hostname, TypeHostname, nil
}

func looksLikeMalformedIPAddress(value string) bool {
	if strings.Contains(value, ":") {
		// A colon is not valid in a DNS hostname. netip.ParseAddr has already
		// rejected this value, so do not let an IPv6-like string fall through.
		return true
	}
	for _, character := range value {
		if (character < '0' || character > '9') && character != '.' {
			return false
		}
	}
	return strings.Contains(value, ".")
}

func hasIPv4NumericPrefix(labels []string) bool {
	if len(labels) < 4 {
		return false
	}
	for _, label := range labels[:4] {
		if label == "" {
			return false
		}
		for _, character := range label {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}
