package service

import (
	"context"
	"errors"
	"sort"
	"time"

	"nmap-api/internal/domain"
)

const (
	DefaultHistoryLimit = 20
	MaxHistoryLimit     = 100
)

var ErrNoComparableScans = errors.New("no comparable completed scans found")

type HistoryRepository interface {
	GetScanHistory(context.Context, string, int) ([]domain.ScanHistory, error)
	GetLatestComparableScans(context.Context, string) ([]domain.ScanHistory, error)
}

type HistoryService struct {
	repository HistoryRepository
}

type HistoryResponse struct {
	Target string               `json:"target"`
	Scans  []domain.ScanHistory `json:"scans"`
}

type PortChange struct {
	ResolvedIP string  `json:"resolved_ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	State      string  `json:"state"`
	Service    *string `json:"service"`
}

type ChangedPort struct {
	ResolvedIP      string  `json:"resolved_ip"`
	Port            int     `json:"port"`
	Protocol        string  `json:"protocol"`
	PreviousState   string  `json:"previous_state"`
	CurrentState    string  `json:"current_state"`
	PreviousService *string `json:"previous_service"`
	CurrentService  *string `json:"current_service"`
}

type ChangesResponse struct {
	Target             string        `json:"target"`
	PreviousScanID     int64         `json:"previous_scan_id"`
	CurrentScanID      int64         `json:"current_scan_id"`
	PreviousStartedAt  *time.Time    `json:"previous_started_at"`
	PreviousFinishedAt *time.Time    `json:"previous_finished_at"`
	CurrentStartedAt   *time.Time    `json:"current_started_at"`
	CurrentFinishedAt  *time.Time    `json:"current_finished_at"`
	AddedPorts         []PortChange  `json:"added_ports"`
	RemovedPorts       []PortChange  `json:"removed_ports"`
	ChangedPorts       []ChangedPort `json:"changed_ports"`
}

func NewHistoryService(repository HistoryRepository) *HistoryService {
	return &HistoryService{repository: repository}
}

func (s *HistoryService) History(ctx context.Context, target string, limit int) (HistoryResponse, error) {
	normalized, _, err := normalizeTarget(target)
	if err != nil {
		return HistoryResponse{}, &ValidationError{Code: "INVALID_TARGET", Message: "target is not a valid IPv4 address, IPv6 address, or hostname"}
	}
	if limit < 1 || limit > MaxHistoryLimit {
		return HistoryResponse{}, &ValidationError{Code: "INVALID_LIMIT", Message: "limit must be between 1 and 100"}
	}

	scans, err := s.repository.GetScanHistory(ctx, normalized, limit)
	if err != nil {
		return HistoryResponse{}, err
	}
	if scans == nil {
		scans = make([]domain.ScanHistory, 0)
	}
	return HistoryResponse{Target: target, Scans: scans}, nil
}

func (s *HistoryService) Changes(ctx context.Context, target string) (ChangesResponse, error) {
	normalized, _, err := normalizeTarget(target)
	if err != nil {
		return ChangesResponse{}, &ValidationError{Code: "INVALID_TARGET", Message: "target is not a valid IPv4 address, IPv6 address, or hostname"}
	}

	scans, err := s.repository.GetLatestComparableScans(ctx, normalized)
	if err != nil {
		return ChangesResponse{}, err
	}
	if len(scans) < 2 {
		return ChangesResponse{}, ErrNoComparableScans
	}
	previous, current := scans[0], scans[1]
	previousUpIPs := comparableUpIPs(previous.HostStatuses, current.HostStatuses)
	previousPorts := indexComparablePorts(previous.Ports, previousUpIPs)
	currentPorts := indexComparablePorts(current.Ports, previousUpIPs)
	keys := make(map[portIdentity]struct{}, len(previousPorts)+len(currentPorts))
	for key := range previousPorts {
		keys[key] = struct{}{}
	}
	for key := range currentPorts {
		keys[key] = struct{}{}
	}
	orderedKeys := make([]portIdentity, 0, len(keys))
	for key := range keys {
		orderedKeys = append(orderedKeys, key)
	}
	sort.Slice(orderedKeys, func(i, j int) bool {
		if orderedKeys[i].ResolvedIP != orderedKeys[j].ResolvedIP {
			return orderedKeys[i].ResolvedIP < orderedKeys[j].ResolvedIP
		}
		if orderedKeys[i].Protocol != orderedKeys[j].Protocol {
			return orderedKeys[i].Protocol < orderedKeys[j].Protocol
		}
		return orderedKeys[i].Port < orderedKeys[j].Port
	})

	response := ChangesResponse{
		Target:             target,
		PreviousScanID:     previous.ScanID,
		CurrentScanID:      current.ScanID,
		PreviousStartedAt:  previous.StartedAt,
		PreviousFinishedAt: previous.FinishedAt,
		CurrentStartedAt:   current.StartedAt,
		CurrentFinishedAt:  current.FinishedAt,
		AddedPorts:         make([]PortChange, 0),
		RemovedPorts:       make([]PortChange, 0),
		ChangedPorts:       make([]ChangedPort, 0),
	}
	for _, key := range orderedKeys {
		before, hadBefore := previousPorts[key]
		after, hasAfter := currentPorts[key]
		switch {
		case !hadBefore && hasAfter:
			response.AddedPorts = append(response.AddedPorts, portChange(after))
		case hadBefore && !hasAfter:
			response.RemovedPorts = append(response.RemovedPorts, portChange(before))
		case hadBefore && hasAfter && (before.State != after.State || !equalOptionalString(before.Service, after.Service)):
			response.ChangedPorts = append(response.ChangedPorts, ChangedPort{
				ResolvedIP:      key.ResolvedIP,
				Port:            key.Port,
				Protocol:        key.Protocol,
				PreviousState:   before.State,
				CurrentState:    after.State,
				PreviousService: before.Service,
				CurrentService:  after.Service,
			})
		}
	}
	return response, nil
}

type portIdentity struct {
	ResolvedIP string
	Port       int
	Protocol   string
}

func indexPorts(ports []domain.ObservedScanPort) map[portIdentity]domain.ObservedScanPort {
	indexed := make(map[portIdentity]domain.ObservedScanPort, len(ports))
	for _, port := range ports {
		indexed[portIdentity{ResolvedIP: port.ResolvedIP, Port: port.Port, Protocol: port.Protocol}] = port
	}
	return indexed
}

func comparableUpIPs(previous, current map[string]string) map[string]struct{} {
	upIPs := make(map[string]struct{})
	for ip, previousStatus := range previous {
		if previousStatus == "up" && current[ip] == "up" {
			upIPs[ip] = struct{}{}
		}
	}
	return upIPs
}

func indexComparablePorts(ports []domain.ObservedScanPort, upIPs map[string]struct{}) map[portIdentity]domain.ObservedScanPort {
	comparable := make([]domain.ObservedScanPort, 0, len(ports))
	for _, port := range ports {
		if _, ok := upIPs[port.ResolvedIP]; ok {
			comparable = append(comparable, port)
		}
	}
	return indexPorts(comparable)
}

func portChange(port domain.ObservedScanPort) PortChange {
	return PortChange{ResolvedIP: port.ResolvedIP, Port: port.Port, Protocol: port.Protocol, State: port.State, Service: port.Service}
}

func equalOptionalString(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
