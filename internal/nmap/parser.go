package nmap

import (
	"encoding/xml"
	"fmt"
	"net"
	"strconv"
	"time"
)

type xmlDocument struct {
	XMLName  xml.Name    `xml:"nmaprun"`
	Start    *string     `xml:"start,attr"`
	Hosts    []xmlHost   `xml:"host"`
	RunStats xmlRunStats `xml:"runstats"`
}

type xmlRunStats struct {
	Finished *xmlFinished `xml:"finished"`
}

type xmlFinished struct {
	Time *string `xml:"time,attr"`
}

type xmlHost struct {
	StartTime *string      `xml:"starttime,attr"`
	EndTime   *string      `xml:"endtime,attr"`
	Status    *xmlStatus   `xml:"status"`
	Addresses []xmlAddress `xml:"address"`
	Ports     []xmlPort    `xml:"ports>port"`
}

type xmlStatus struct {
	State *string `xml:"state,attr"`
}

type xmlAddress struct {
	Address *string `xml:"addr,attr"`
	Type    *string `xml:"addrtype,attr"`
}

type xmlPort struct {
	Number   *string       `xml:"portid,attr"`
	Protocol *string       `xml:"protocol,attr"`
	State    *xmlPortState `xml:"state"`
	Service  *xmlService   `xml:"service"`
}

type xmlPortState struct {
	State  *string `xml:"state,attr"`
	Reason *string `xml:"reason,attr"`
}

type xmlService struct {
	Name *string `xml:"name,attr"`
}

// ParseXML parses one Nmap XML document for the requested target.
func ParseXML(target string, data []byte) (ScanResult, error) {
	if target == "" {
		return ScanResult{}, fmt.Errorf("Nmap target must not be empty")
	}

	var document xmlDocument
	if err := xml.Unmarshal(data, &document); err != nil {
		return ScanResult{}, fmt.Errorf("decode Nmap XML: %w", err)
	}
	if document.XMLName.Local != "nmaprun" {
		return ScanResult{}, fmt.Errorf("invalid Nmap XML root element %q", document.XMLName.Local)
	}
	if len(document.Hosts) == 0 {
		return ScanResult{}, fmt.Errorf("Nmap XML contains no host results")
	}

	startedAt, err := parseTimestamp(document.Start, "nmaprun start")
	if err != nil {
		return ScanResult{}, err
	}

	var finishedValue *string
	if document.RunStats.Finished != nil {
		finishedValue = document.RunStats.Finished.Time
	}
	finishedAt, err := parseTimestamp(finishedValue, "runstats finished time")
	if err != nil {
		return ScanResult{}, err
	}

	result := ScanResult{
		Target:     target,
		StartedAt:  startedAt,
		FinishedAt: finishedAt,
		Hosts:      make([]HostResult, 0, len(document.Hosts)),
	}
	seenIPs := make(map[string]struct{})

	for hostIndex, xmlHost := range document.Hosts {
		host, err := parseHost(xmlHost, hostIndex+1)
		if err != nil {
			return ScanResult{}, err
		}
		for _, address := range host.addresses {
			key := net.ParseIP(address).String()
			if _, exists := seenIPs[key]; exists {
				continue
			}
			seenIPs[key] = struct{}{}

			ip := address
			result.Hosts = append(result.Hosts, HostResult{
				ResolvedIP: &ip,
				Status:     host.status,
				StartedAt:  host.startedAt,
				FinishedAt: host.finishedAt,
				Ports:      host.ports,
			})
		}
	}

	return result, nil
}

type parsedHost struct {
	addresses  []string
	status     *string
	startedAt  *time.Time
	finishedAt *time.Time
	ports      []Port
}

func parseHost(host xmlHost, hostIndex int) (parsedHost, error) {
	addresses := make([]string, 0, len(host.Addresses))
	seen := make(map[string]struct{}, len(host.Addresses))
	for _, address := range host.Addresses {
		if address.Address == nil || address.Type == nil || (*address.Type != "ipv4" && *address.Type != "ipv6") {
			continue
		}
		parsedIP := net.ParseIP(*address.Address)
		if parsedIP == nil {
			return parsedHost{}, fmt.Errorf("Nmap host %d contains an invalid %s address", hostIndex, *address.Type)
		}
		key := parsedIP.String()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		addresses = append(addresses, *address.Address)
	}
	if len(addresses) == 0 {
		return parsedHost{}, fmt.Errorf("Nmap host %d has no usable IPv4 or IPv6 address", hostIndex)
	}

	var status *string
	if host.Status != nil {
		status = host.Status.State
	}
	startedAt, err := parseTimestamp(host.StartTime, fmt.Sprintf("host %d starttime", hostIndex))
	if err != nil {
		return parsedHost{}, err
	}
	finishedAt, err := parseTimestamp(host.EndTime, fmt.Sprintf("host %d endtime", hostIndex))
	if err != nil {
		return parsedHost{}, err
	}

	ports := make([]Port, 0, len(host.Ports))
	for portIndex, xmlPort := range host.Ports {
		port, err := parsePort(xmlPort, hostIndex, portIndex+1)
		if err != nil {
			return parsedHost{}, err
		}
		ports = append(ports, port)
	}

	return parsedHost{
		addresses:  addresses,
		status:     status,
		startedAt:  startedAt,
		finishedAt: finishedAt,
		ports:      ports,
	}, nil
}

func parsePort(port xmlPort, hostIndex, portIndex int) (Port, error) {
	field := fmt.Sprintf("Nmap host %d port %d", hostIndex, portIndex)
	if port.Number == nil {
		return Port{}, fmt.Errorf("%s is missing portid", field)
	}
	number, err := strconv.Atoi(*port.Number)
	if err != nil || number < 0 || number > 65535 {
		return Port{}, fmt.Errorf("%s has an invalid portid", field)
	}
	if port.Protocol == nil || *port.Protocol == "" {
		return Port{}, fmt.Errorf("%s is missing protocol", field)
	}
	if port.State == nil || port.State.State == nil || *port.State.State == "" {
		return Port{}, fmt.Errorf("%s is missing state", field)
	}

	var serviceName *string
	if port.Service != nil {
		serviceName = port.Service.Name
	}
	var reason *string
	if port.State != nil {
		reason = port.State.Reason
	}

	return Port{
		Number:      number,
		Protocol:    *port.Protocol,
		State:       *port.State.State,
		ServiceName: serviceName,
		Reason:      reason,
	}, nil
}

func parseTimestamp(value *string, field string) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}
	seconds, err := strconv.ParseInt(*value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("Nmap XML contains an invalid %s timestamp", field)
	}
	parsed := time.Unix(seconds, 0).UTC()
	return &parsed, nil
}
