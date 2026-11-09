package service

import (
	"context"
	"testing"
	"time"

	"nmap-api/internal/domain"
)

// TestChangesComparePortsByResolvedIPAndDoNotSynthesizeClosedState verifies mocked histories report open-to-closed changes and added/removed ports by IP without inventing closed states for missing observations.
func TestChangesComparePortsByResolvedIPAndDoNotSynthesizeClosedState(t *testing.T) {
	started := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	service := NewHistoryService(fakeHistoryRepository{scans: []domain.ScanHistory{
		{
			ScanID: 10, Status: "completed", StartedAt: &started, FinishedAt: timePtr(started.Add(time.Minute)),
			ResolvedIPs:  []string{"192.0.2.1", "192.0.2.2"},
			HostStatuses: map[string]string{"192.0.2.1": "up", "192.0.2.2": "up"},
			Ports: []domain.ObservedScanPort{
				{ResolvedIP: "192.0.2.1", Port: 22, Protocol: "tcp", State: "open", Service: stringPtr("ssh")},
				{ResolvedIP: "192.0.2.1", Port: 80, Protocol: "tcp", State: "open", Service: stringPtr("http")},
				{ResolvedIP: "192.0.2.2", Port: 443, Protocol: "tcp", State: "filtered", Service: stringPtr("https")},
				{ResolvedIP: "192.0.2.2", Port: 444, Protocol: "tcp", State: "filtered", Service: stringPtr("https-alt")},
			},
		},
		{
			ScanID: 11, Status: "completed", StartedAt: timePtr(started.Add(2 * time.Minute)), FinishedAt: timePtr(started.Add(3 * time.Minute)),
			ResolvedIPs:  []string{"192.0.2.1", "192.0.2.2"},
			HostStatuses: map[string]string{"192.0.2.1": "up", "192.0.2.2": "up"},
			Ports: []domain.ObservedScanPort{
				{ResolvedIP: "192.0.2.1", Port: 22, Protocol: "tcp", State: "closed", Service: stringPtr("ssh")},
				{ResolvedIP: "192.0.2.1", Port: 443, Protocol: "tcp", State: "open", Service: stringPtr("https")},
				{ResolvedIP: "192.0.2.1", Port: 8080, Protocol: "tcp", State: "open", Service: stringPtr("http-alt")},
				{ResolvedIP: "192.0.2.2", Port: 443, Protocol: "tcp", State: "open", Service: stringPtr("https")},
			},
		},
	}})

	changes, err := service.Changes(context.Background(), "history.example")
	if err != nil {
		t.Fatalf("Changes returned error: %v", err)
	}
	if changes.PreviousScanID != 10 || changes.CurrentScanID != 11 {
		t.Fatalf("unexpected scan pair: previous=%d current=%d", changes.PreviousScanID, changes.CurrentScanID)
	}
	if len(changes.AddedPorts) != 2 || changes.AddedPorts[0].ResolvedIP != "192.0.2.1" || changes.AddedPorts[0].Port != 443 || changes.AddedPorts[1].Port != 8080 {
		t.Fatalf("unexpected added ports: %#v", changes.AddedPorts)
	}
	if len(changes.RemovedPorts) != 2 || changes.RemovedPorts[0].ResolvedIP != "192.0.2.1" || changes.RemovedPorts[0].Port != 80 || changes.RemovedPorts[1].ResolvedIP != "192.0.2.2" || changes.RemovedPorts[1].Port != 444 {
		t.Fatalf("unexpected removed ports: %#v", changes.RemovedPorts)
	}
	if changes.RemovedPorts[1].State != "filtered" {
		t.Fatalf("missing observation was converted to a different state: %#v", changes.RemovedPorts[1])
	}
	if len(changes.ChangedPorts) != 2 || changes.ChangedPorts[0].ResolvedIP != "192.0.2.1" || changes.ChangedPorts[0].Port != 22 || changes.ChangedPorts[0].PreviousState != "open" || changes.ChangedPorts[0].CurrentState != "closed" || changes.ChangedPorts[1].ResolvedIP != "192.0.2.2" || changes.ChangedPorts[1].Port != 443 || changes.ChangedPorts[1].PreviousState != "filtered" || changes.ChangedPorts[1].CurrentState != "open" {
		t.Fatalf("unexpected changed ports: %#v", changes.ChangedPorts)
	}
}

// TestChangesReportsOpenToFilteredTransition verifies an explicit filtered observation is a changed port, not a removal.
func TestChangesReportsOpenToFilteredTransition(t *testing.T) {
	started := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	historyService := NewHistoryService(fakeHistoryRepository{scans: []domain.ScanHistory{
		{
			ScanID: 30, Status: "completed", StartedAt: &started, FinishedAt: timePtr(started.Add(time.Minute)),
			ResolvedIPs: []string{"192.0.2.80"}, HostStatuses: map[string]string{"192.0.2.80": "up"},
			Ports: []domain.ObservedScanPort{{ResolvedIP: "192.0.2.80", Port: 8080, Protocol: "tcp", State: "open"}},
		},
		{
			ScanID: 31, Status: "completed", StartedAt: timePtr(started.Add(2 * time.Minute)), FinishedAt: timePtr(started.Add(3 * time.Minute)),
			ResolvedIPs: []string{"192.0.2.80"}, HostStatuses: map[string]string{"192.0.2.80": "up"},
			Ports: []domain.ObservedScanPort{{ResolvedIP: "192.0.2.80", Port: 8080, Protocol: "tcp", State: "filtered", Reason: stringPtr("no-response")}},
		},
	}})

	changes, err := historyService.Changes(context.Background(), "transition.example")
	if err != nil {
		t.Fatalf("Changes returned error: %v", err)
	}
	if len(changes.ChangedPorts) != 1 || changes.ChangedPorts[0].Port != 8080 || changes.ChangedPorts[0].PreviousState != "open" || changes.ChangedPorts[0].CurrentState != "filtered" {
		t.Fatalf("expected port 8080 open-to-filtered change, got %#v", changes.ChangedPorts)
	}
	if len(changes.RemovedPorts) != 0 {
		t.Fatalf("explicit filtered observation was reported as removed: %#v", changes.RemovedPorts)
	}
}

// TestChangesDoNotRemovePortsWhenHostIsDown verifies a host that is down in the newer mocked scan produces no port additions, removals, or changes.
func TestChangesDoNotRemovePortsWhenHostIsDown(t *testing.T) {
	started := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	historyService := NewHistoryService(fakeHistoryRepository{scans: []domain.ScanHistory{
		{
			ScanID: 20, Status: "completed", StartedAt: &started, FinishedAt: timePtr(started.Add(time.Minute)),
			ResolvedIPs: []string{"192.0.2.50"}, HostStatuses: map[string]string{"192.0.2.50": "up"},
			Ports: []domain.ObservedScanPort{
				{ResolvedIP: "192.0.2.50", Port: 22, Protocol: "tcp", State: "open"},
				{ResolvedIP: "192.0.2.50", Port: 80, Protocol: "tcp", State: "open"},
			},
		},
		{
			ScanID: 21, Status: "completed", StartedAt: timePtr(started.Add(2 * time.Minute)), FinishedAt: timePtr(started.Add(3 * time.Minute)),
			ResolvedIPs: []string{"192.0.2.50"}, HostStatuses: map[string]string{"192.0.2.50": "down"},
			Ports: []domain.ObservedScanPort{},
		},
	}})

	changes, err := historyService.Changes(context.Background(), "history.example")
	if err != nil {
		t.Fatalf("Changes returned error: %v", err)
	}
	if len(changes.RemovedPorts) != 0 || len(changes.AddedPorts) != 0 || len(changes.ChangedPorts) != 0 {
		t.Fatalf("down host generated port changes: %#v", changes)
	}
}

// TestHistoryReturnsEmptyWhenRepositoryHasNoScans verifies an empty repository result becomes a non-nil empty scans list for the requested target.
func TestHistoryReturnsEmptyWhenRepositoryHasNoScans(t *testing.T) {
	repo := fakeHistoryRepository{}
	historyService := NewHistoryService(repo)
	result, err := historyService.History(context.Background(), "history.example", DefaultHistoryLimit)
	if err != nil {
		t.Fatalf("History returned error: %v", err)
	}
	if result.Target != "history.example" || result.Scans == nil || len(result.Scans) != 0 {
		t.Fatalf("expected target with empty non-nil scans, got %#v", result)
	}
}

type fakeHistoryRepository struct {
	scans []domain.ScanHistory
}

func (r fakeHistoryRepository) GetScanHistory(context.Context, string, int) ([]domain.ScanHistory, error) {
	return nil, nil
}

func (r fakeHistoryRepository) GetLatestComparableScans(context.Context, string) ([]domain.ScanHistory, error) {
	return r.scans, nil
}

func stringPtr(value string) *string { return &value }

func timePtr(value time.Time) *time.Time { return &value }
