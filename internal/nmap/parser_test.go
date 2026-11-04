package nmap

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseXML_MultipleHostsAndPortStates(t *testing.T) {
	data := readFixture(t, "multi_host.xml")
	result, err := ParseXML("scanme.example", data)
	if err != nil {
		t.Fatalf("ParseXML returned error: %v", err)
	}

	if result.Target != "scanme.example" {
		t.Fatalf("expected target scanme.example, got %q", result.Target)
	}
	if result.StartedAt == nil || !result.StartedAt.Equal(time.Unix(1700000000, 0).UTC()) {
		t.Fatalf("unexpected scan start time: %v", result.StartedAt)
	}
	if result.FinishedAt == nil || !result.FinishedAt.Equal(time.Unix(1700000005, 0).UTC()) {
		t.Fatalf("unexpected scan finish time: %v", result.FinishedAt)
	}
	if len(result.Hosts) != 2 {
		t.Fatalf("expected two unique host results, got %d", len(result.Hosts))
	}

	ips := []string{*result.Hosts[0].ResolvedIP, *result.Hosts[1].ResolvedIP}
	if !reflect.DeepEqual(ips, []string{"192.0.2.10", "2001:db8::10"}) {
		t.Fatalf("unexpected resolved IPs: %v", ips)
	}
	if result.Hosts[0].Status == nil || *result.Hosts[0].Status != "up" {
		t.Fatalf("unexpected first host status: %v", result.Hosts[0].Status)
	}
	if result.Hosts[0].StartedAt == nil || !result.Hosts[0].StartedAt.Equal(time.Unix(1700000001, 0).UTC()) {
		t.Fatalf("unexpected first host start time: %v", result.Hosts[0].StartedAt)
	}
	if result.Hosts[0].FinishedAt == nil || !result.Hosts[0].FinishedAt.Equal(time.Unix(1700000002, 0).UTC()) {
		t.Fatalf("unexpected first host finish time: %v", result.Hosts[0].FinishedAt)
	}

	states := make(map[int]string, len(result.Hosts[0].Ports))
	for _, port := range result.Hosts[0].Ports {
		states[port.Number] = port.State
	}
	for port, want := range map[int]string{
		80:   "open",
		22:   "closed",
		443:  "filtered",
		8443: "open|filtered",
	} {
		if got := states[port]; got != want {
			t.Errorf("port %d state = %q, want %q", port, got, want)
		}
	}
	if result.Hosts[0].Ports[0].Protocol != "tcp" {
		t.Errorf("expected tcp protocol, got %q", result.Hosts[0].Ports[0].Protocol)
	}
	if got := result.Hosts[0].Ports[0].ServiceName; got == nil || *got != "http" {
		t.Errorf("expected http service, got %v", got)
	}
	if got := result.Hosts[0].Ports[0].Reason; got == nil || *got != "syn-ack" {
		t.Errorf("expected syn-ack reason, got %v", got)
	}
	if got := result.Hosts[0].Ports[3].ServiceName; got != nil {
		t.Errorf("expected missing service to remain nil, got %v", *got)
	}
	if got := result.Hosts[0].Ports[3].Reason; got != nil {
		t.Errorf("expected missing reason to remain nil, got %v", *got)
	}
	if result.Hosts[1].Status == nil || *result.Hosts[1].Status != "up" {
		t.Errorf("unexpected second host status: %v", result.Hosts[1].Status)
	}
}

func TestParseXML_HostWithNoPorts(t *testing.T) {
	result, err := ParseXML("198.51.100.25", readFixture(t, "no_ports.xml"))
	if err != nil {
		t.Fatalf("ParseXML returned error: %v", err)
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("expected one host, got %d", len(result.Hosts))
	}
	if result.Hosts[0].Ports == nil || len(result.Hosts[0].Ports) != 0 {
		t.Fatalf("expected an empty, non-nil port slice, got %#v", result.Hosts[0].Ports)
	}
	if result.Hosts[0].StartedAt != nil || result.Hosts[0].FinishedAt != nil {
		t.Fatal("expected absent host times to remain nil")
	}
}

func TestParseXML_MalformedDocument(t *testing.T) {
	_, err := ParseXML("example.test", []byte(`<nmaprun><host>`))
	if err == nil || !strings.Contains(err.Error(), "decode Nmap XML") {
		t.Fatalf("expected a clear malformed XML error, got %v", err)
	}
}

func TestParseXML_RejectsUnusableHost(t *testing.T) {
	data := []byte(`<nmaprun><host><status state="up"/><address addr="host.example" addrtype="hostname"/></host></nmaprun>`)
	_, err := ParseXML("host.example", data)
	if err == nil || !strings.Contains(err.Error(), "no usable IPv4 or IPv6 address") {
		t.Fatalf("expected a missing usable IP error, got %v", err)
	}
}

func TestParseXML_RejectsInvalidPortAndTimestamp(t *testing.T) {
	tests := []struct {
		name string
		xml  string
		want string
	}{
		{
			name: "missing state",
			xml:  `<nmaprun><host><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"/></ports></host></nmaprun>`,
			want: "missing state",
		},
		{
			name: "invalid timestamp",
			xml:  `<nmaprun start="not-a-time"><host><address addr="192.0.2.1" addrtype="ipv4"/></host></nmaprun>`,
			want: "invalid nmaprun start timestamp",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseXML("example.test", []byte(test.xml))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected error containing %q, got %v", test.want, err)
			}
		})
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read XML fixture %s: %v", name, err)
	}
	return data
}
