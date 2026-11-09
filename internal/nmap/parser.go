package nmap

import (
	"encoding/xml"
	"fmt"
	"net"
	"strconv"
	"strings"
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
	StartTime  *string         `xml:"starttime,attr"`
	EndTime    *string         `xml:"endtime,attr"`
	Status     *xmlStatus      `xml:"status"`
	Addresses  []xmlAddress    `xml:"address"`
	Ports      []xmlPort       `xml:"ports>port"`
	ExtraPorts []xmlExtraPorts `xml:"ports>extraports"`
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

type xmlExtraPorts struct {
	State   *string          `xml:"state,attr"`
	Count   *string          `xml:"count,attr"`
	Reasons []xmlExtraReason `xml:"extrareasons"`
}

type xmlExtraReason struct {
	Reason   *string `xml:"reason,attr"`
	Count    *string `xml:"count,attr"`
	Protocol *string `xml:"proto,attr"`
	Ports    *string `xml:"ports,attr"`
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
	portIndexes := make(map[portIdentity]int, len(host.Ports))
	explicitPorts := make(map[portIdentity]struct{}, len(host.Ports))
	for portIndex, xmlPort := range host.Ports {
		port, err := parsePort(xmlPort, hostIndex, portIndex+1)
		if err != nil {
			return parsedHost{}, err
		}
		identity := portIdentity{Protocol: port.Protocol, Number: port.Number}
		if _, exists := portIndexes[identity]; exists {
			continue
		}
		portIndexes[identity] = len(ports)
		explicitPorts[identity] = struct{}{}
		ports = append(ports, port)
	}

	for extraIndex, extra := range host.ExtraPorts {
		if extra.State == nil || *extra.State == "" {
			continue
		}
		reasonCounts := 0
		allReasonsMapped := len(extra.Reasons) > 0
		for reasonIndex, xmlReason := range extra.Reasons {
			if xmlReason.Ports == nil || *xmlReason.Ports == "" || xmlReason.Protocol == nil || *xmlReason.Protocol == "" {
				allReasonsMapped = false
				continue
			}
			field := fmt.Sprintf("Nmap host %d extraports %d reason %d", hostIndex, extraIndex+1, reasonIndex+1)
			portNumbers, err := parsePortList(*xmlReason.Ports, field)
			if err != nil {
				return parsedHost{}, err
			}
			if xmlReason.Count != nil {
				count, err := parsePortCount(*xmlReason.Count, field)
				if err != nil {
					return parsedHost{}, err
				}
				if count != len(portNumbers) {
					return parsedHost{}, fmt.Errorf("%s count does not match its listed ports", field)
				}
				reasonCounts += count
			} else {
				allReasonsMapped = false
			}

			for _, number := range portNumbers {
				identity := portIdentity{Protocol: *xmlReason.Protocol, Number: number}
				if existingIndex, exists := portIndexes[identity]; exists {
					// An individual <port> entry is more specific than an aggregate.
					if _, explicit := explicitPorts[identity]; explicit {
						continue
					}
					existing := ports[existingIndex]
					if existing.State != *extra.State || !equalOptionalString(existing.Reason, xmlReason.Reason) {
						return parsedHost{}, fmt.Errorf("%s duplicates a port with conflicting aggregate state", field)
					}
					continue
				}
				var reason *string
				if xmlReason.Reason != nil {
					reason = xmlReason.Reason
				}
				portIndexes[identity] = len(ports)
				ports = append(ports, Port{
					Number:   number,
					Protocol: *xmlReason.Protocol,
					State:    *extra.State,
					Reason:   reason,
				})
			}
		}
		if allReasonsMapped && extra.Count != nil {
			count, err := parsePortCount(*extra.Count, fmt.Sprintf("Nmap host %d extraports %d", hostIndex, extraIndex+1))
			if err != nil {
				return parsedHost{}, err
			}
			if count != reasonCounts {
				return parsedHost{}, fmt.Errorf("Nmap host %d extraports %d count does not match its reason counts", hostIndex, extraIndex+1)
			}
		}
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

type portIdentity struct {
	Protocol string
	Number   int
}

func parsePortList(value, field string) ([]int, error) {
	numbers := make([]int, 0)
	seen := make(map[int]struct{})
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, fmt.Errorf("%s contains an empty port range", field)
		}
		bounds := strings.Split(item, "-")
		if len(bounds) > 2 {
			return nil, fmt.Errorf("%s contains an invalid port range %q", field, item)
		}
		first, err := parsePortNumber(bounds[0], field)
		if err != nil {
			return nil, err
		}
		last := first
		if len(bounds) == 2 {
			last, err = parsePortNumber(bounds[1], field)
			if err != nil {
				return nil, err
			}
			if first > last {
				return nil, fmt.Errorf("%s contains a descending port range %q", field, item)
			}
		}
		for number := first; number <= last; number++ {
			if _, exists := seen[number]; exists {
				return nil, fmt.Errorf("%s lists port %d more than once", field, number)
			}
			seen[number] = struct{}{}
			numbers = append(numbers, number)
		}
	}
	return numbers, nil
}

func parsePortNumber(value, field string) (int, error) {
	number, err := strconv.Atoi(value)
	if err != nil || number < 0 || number > 65535 {
		return 0, fmt.Errorf("%s contains an invalid port number %q", field, value)
	}
	return number, nil
}

func parsePortCount(value, field string) (int, error) {
	count, err := strconv.Atoi(value)
	if err != nil || count < 0 {
		return 0, fmt.Errorf("%s contains an invalid count %q", field, value)
	}
	return count, nil
}

func equalOptionalString(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
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
