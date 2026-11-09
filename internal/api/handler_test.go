package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nmap-api/internal/domain"
	"nmap-api/internal/service"
)

// TestPostScansAcceptsAllowedIPsAndHostname verifies normalized allowed targets return 202 and create one pending job per target.
func TestPostScansAcceptsAllowedIPsAndHostname(t *testing.T) {
	repo := &recordingScanRepository{}
	handler := newTestHandler(t, repo, []string{"192.0.2.1", "Example.COM", "2001:db8::1"}, 20, 60)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(`{"targets":["192.0.2.1","EXAMPLE.com","2001:0db8:0:0:0:0:0:1"]}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusAccepted, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", response.Header().Get("Content-Type"))
	}
	var accepted service.AcceptedScan
	if err := json.Unmarshal(response.Body.Bytes(), &accepted); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if accepted.Status != "accepted" || len(accepted.Targets) != 3 || accepted.RequestID == "" {
		t.Fatalf("unexpected accepted response: %#v", accepted)
	}
	if repo.calls != 1 || len(repo.jobs) != 3 {
		t.Fatalf("expected one atomic repository call with 3 jobs; calls=%d jobs=%d", repo.calls, len(repo.jobs))
	}
	if repo.jobs[0].TargetType != "ip" || repo.jobs[1].TargetType != "hostname" || repo.jobs[2].TargetType != "ip" {
		t.Fatalf("unexpected target types: %#v", repo.jobs)
	}
	for _, job := range repo.jobs {
		if job.Status != "pending" || job.TimeoutSeconds != 60 {
			t.Fatalf("unexpected job defaults: %#v", job)
		}
	}
}

// TestPostScansRejectsMixedBatchWithoutPersistence verifies one disallowed hostname returns 400 and prevents every job from reaching the repository.
func TestPostScansRejectsMixedBatchWithoutPersistence(t *testing.T) {
	repo := &recordingScanRepository{}
	handler := newTestHandler(t, repo, []string{"192.0.2.1", "allowed.example"}, 20, 60)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(`{"targets":["192.0.2.1","not-allowed.example"]}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	assertErrorResponse(t, response, http.StatusBadRequest, "TARGET_NOT_ALLOWED")
	if repo.calls != 0 {
		t.Fatalf("unauthorized mixed batch reached repository %d times", repo.calls)
	}
}

// TestPostScansEmptyAllowlistDeniesAll verifies an IP target returns 400 and is not persisted when the allowlist is empty.
func TestPostScansEmptyAllowlistDeniesAll(t *testing.T) {
	repo := &recordingScanRepository{}
	handler := newTestHandler(t, repo, nil, 20, 60)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(`{"targets":["192.0.2.1"]}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	assertErrorResponse(t, response, http.StatusBadRequest, "TARGET_NOT_ALLOWED")
	if repo.calls != 0 {
		t.Fatalf("empty allowlist reached repository %d times", repo.calls)
	}
}

// TestPostScansRejectsInvalidLimitsAndMalformedJSON verifies invalid scan inputs return 400 without calling the persistence repository.
func TestPostScansRejectsInvalidLimitsAndMalformedJSON(t *testing.T) {
	tests := []struct {
		name     string
		maxBatch int
		body     string
		wantCode string
	}{
		{name: "timeout above maximum", maxBatch: 2, body: `{"targets":["allowed.example"],"timeout_seconds":121}`, wantCode: "INVALID_TIMEOUT"},
		{name: "batch too large", maxBatch: 1, body: `{"targets":["allowed.example","192.0.2.1"]}`, wantCode: "BATCH_TOO_LARGE"},
		{name: "malformed target", maxBatch: 2, body: `{"targets":["bad!hostname"]}`, wantCode: "INVALID_TARGET"},
		{name: "malformed JSON", maxBatch: 2, body: `{"targets":[`, wantCode: "INVALID_JSON"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo := &recordingScanRepository{}
			handler := newTestHandler(t, repo, []string{"allowed.example", "192.0.2.1"}, test.maxBatch, 60)
			request := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(test.body))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertErrorResponse(t, response, http.StatusBadRequest, test.wantCode)
			if repo.calls != 0 {
				t.Fatalf("invalid request reached repository %d times", repo.calls)
			}
		})
	}
}

// TestScansEndpointRejectsUnsupportedMethods verifies GET receives 405 with an Allow: POST header on the scan submission route.
func TestScansEndpointRejectsUnsupportedMethods(t *testing.T) {
	repo := &recordingScanRepository{}
	handler := newTestHandler(t, repo, []string{"192.0.2.1"}, 20, 60)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	assertErrorResponse(t, response, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
	if response.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("Allow header = %q, want POST", response.Header().Get("Allow"))
	}
}

// TestGetScanHistoryReturnsJSONAndEmptyArray verifies a case-insensitive hostname query with a limit returns 200 and an empty scans array.
func TestGetScanHistoryReturnsJSONAndEmptyArray(t *testing.T) {
	repo := &recordingScanRepository{}
	handler := newTestHandler(t, repo, nil, 20, 60)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/targets/EXAMPLE.com/scans?limit=5", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("unexpected history response: status=%d content-type=%q body=%s", response.Code, response.Header().Get("Content-Type"), response.Body.String())
	}
	if repo.historyTarget != "example.com" || repo.historyLimit != 5 {
		t.Fatalf("history query used target=%q limit=%d", repo.historyTarget, repo.historyLimit)
	}
	var result struct {
		Target string               `json:"target"`
		Scans  []domain.ScanHistory `json:"scans"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode history response: %v", err)
	}
	if result.Target != "EXAMPLE.com" || result.Scans == nil || len(result.Scans) != 0 {
		t.Fatalf("expected original target and empty scans array, got %#v", result)
	}
}

// TestGetScanHistoryFiltersPortsByState verifies every supported filter and keeps scans whose ports are all excluded.
func TestGetScanHistoryFiltersPortsByState(t *testing.T) {
	history := []domain.ScanHistory{
		{
			ScanID: 61, Status: "completed", ResolvedIPs: []string{"192.0.2.61"},
			Ports: []domain.ObservedScanPort{
				{ResolvedIP: "192.0.2.61", Port: 22, Protocol: "tcp", State: "open"},
				{ResolvedIP: "192.0.2.61", Port: 80, Protocol: "tcp", State: "closed"},
				{ResolvedIP: "192.0.2.61", Port: 8080, Protocol: "tcp", State: "filtered"},
				{ResolvedIP: "192.0.2.61", Port: 8443, Protocol: "tcp", State: "open|filtered"},
			},
		},
		{
			ScanID: 62, Status: "completed", ResolvedIPs: []string{"192.0.2.62"},
			Ports: []domain.ObservedScanPort{{ResolvedIP: "192.0.2.62", Port: 8081, Protocol: "tcp", State: "filtered"}},
		},
	}
	tests := []struct {
		name       string
		stateQuery string
		wantPorts  [][]int
	}{
		{name: "default open and closed", wantPorts: [][]int{{22, 80}, {}}},
		{name: "open", stateQuery: "&state=open", wantPorts: [][]int{{22}, {}}},
		{name: "closed", stateQuery: "&state=closed", wantPorts: [][]int{{80}, {}}},
		{name: "filtered", stateQuery: "&state=filtered", wantPorts: [][]int{{8080}, {8081}}},
		{name: "all", stateQuery: "&state=all", wantPorts: [][]int{{22, 80, 8080, 8443}, {8081}}},
		{name: "case insensitive", stateQuery: "&state=OPEN", wantPorts: [][]int{{22}, {}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo := &recordingScanRepository{history: history}
			handler := newTestHandler(t, repo, nil, 20, 60)
			request := httptest.NewRequest(http.MethodGet, "/api/v1/targets/192.0.2.61/scans?limit=5"+test.stateQuery, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
			}
			var result struct {
				Scans []domain.ScanHistory `json:"scans"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if len(result.Scans) != len(test.wantPorts) {
				t.Fatalf("got %d scans, want %d", len(result.Scans), len(test.wantPorts))
			}
			for scanIndex, wantPorts := range test.wantPorts {
				if len(result.Scans[scanIndex].Ports) != len(wantPorts) {
					t.Fatalf("scan %d has %d ports, want %d", result.Scans[scanIndex].ScanID, len(result.Scans[scanIndex].Ports), len(wantPorts))
				}
				for portIndex, wantPort := range wantPorts {
					if result.Scans[scanIndex].Ports[portIndex].Port != wantPort {
						t.Errorf("scan %d port[%d] = %d, want %d", result.Scans[scanIndex].ScanID, portIndex, result.Scans[scanIndex].Ports[portIndex].Port, wantPort)
					}
				}
			}
			if repo.historyLimit != 5 {
				t.Errorf("history limit = %d, want 5", repo.historyLimit)
			}
		})
	}
}

// TestGetScanHistoryRejectsUnsupportedState verifies an unknown state returns 400 without querying history.
func TestGetScanHistoryRejectsUnsupportedState(t *testing.T) {
	repo := &recordingScanRepository{}
	handler := newTestHandler(t, repo, nil, 20, 60)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/targets/192.0.2.1/scans?state=unknown", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	assertErrorResponse(t, response, http.StatusBadRequest, "INVALID_STATE")
	if repo.historyCalls != 0 {
		t.Fatalf("invalid state queried history %d times", repo.historyCalls)
	}
}

// TestGetChangesEndpointReturnsComparableDiff verifies the handler returns 200 with an open-to-filtered port change from supplied history data.
func TestGetChangesEndpointReturnsComparableDiff(t *testing.T) {
	previousStarted := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	currentStarted := previousStarted.Add(time.Hour)
	previous := domain.ScanHistory{ScanID: 41, Status: "completed", StartedAt: &previousStarted, FinishedAt: timePtr(previousStarted.Add(time.Minute)), ResolvedIPs: []string{"192.0.2.1"}, HostStatuses: map[string]string{"192.0.2.1": "up"}, Ports: []domain.ObservedScanPort{{ResolvedIP: "192.0.2.1", Port: 80, Protocol: "tcp", State: "open"}}}
	current := domain.ScanHistory{ScanID: 42, Status: "completed", StartedAt: &currentStarted, FinishedAt: timePtr(currentStarted.Add(time.Minute)), ResolvedIPs: []string{"192.0.2.1"}, HostStatuses: map[string]string{"192.0.2.1": "up"}, Ports: []domain.ObservedScanPort{{ResolvedIP: "192.0.2.1", Port: 80, Protocol: "tcp", State: "filtered"}}}
	repo := &recordingScanRepository{history: []domain.ScanHistory{current, previous}, comparableScans: []domain.ScanHistory{previous, current}}
	handler := newTestHandler(t, repo, nil, 20, 60)
	historyRequest := httptest.NewRequest(http.MethodGet, "/api/v1/targets/192.0.2.1/scans", nil)
	historyResponse := httptest.NewRecorder()
	handler.ServeHTTP(historyResponse, historyRequest)
	var historyResult struct {
		Scans []domain.ScanHistory `json:"scans"`
	}
	if err := json.Unmarshal(historyResponse.Body.Bytes(), &historyResult); err != nil {
		t.Fatalf("decode default-filtered history: %v", err)
	}
	if len(historyResult.Scans) != 2 || len(historyResult.Scans[0].Ports) != 0 {
		t.Fatalf("default history should keep the scan but hide its filtered port: %#v", historyResult.Scans)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/targets/192.0.2.1/changes", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("unexpected changes response: status=%d content-type=%q body=%s", response.Code, response.Header().Get("Content-Type"), response.Body.String())
	}
	var changes service.ChangesResponse
	if err := json.Unmarshal(response.Body.Bytes(), &changes); err != nil {
		t.Fatalf("decode changes response: %v", err)
	}
	if changes.PreviousScanID != 41 || changes.CurrentScanID != 42 || len(changes.ChangedPorts) != 1 || changes.ChangedPorts[0].ResolvedIP != "192.0.2.1" || changes.ChangedPorts[0].PreviousState != "open" || changes.ChangedPorts[0].CurrentState != "filtered" || len(changes.RemovedPorts) != 0 {
		t.Fatalf("unexpected changes response body: %#v", changes)
	}
	for _, timestamp := range []*time.Time{changes.PreviousStartedAt, changes.PreviousFinishedAt, changes.CurrentStartedAt, changes.CurrentFinishedAt} {
		if timestamp == nil {
			t.Fatal("expected scan timestamps in changes response")
		}
		if _, offset := timestamp.Zone(); offset != 5*60*60+30*60 {
			t.Errorf("timestamp offset = %d seconds, want IST offset %d", offset, 5*60*60+30*60)
		}
	}
}

// TestGetScanHistoryReturnsExpandedPorts verifies a filtered-state query includes the filtered port and reason in history JSON.
func TestGetScanHistoryReturnsExpandedPorts(t *testing.T) {
	reason := "no-response"
	startedAt := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Minute)
	repo := &recordingScanRepository{history: []domain.ScanHistory{{
		ScanID: 50, Status: "completed", StartedAt: &startedAt, FinishedAt: &finishedAt, ResolvedIPs: []string{"192.0.2.80"},
		Ports: []domain.ObservedScanPort{{ResolvedIP: "192.0.2.80", Port: 8080, Protocol: "tcp", State: "filtered", Reason: &reason}},
	}}}
	handler := newTestHandler(t, repo, nil, 20, 60)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/targets/192.0.2.80/scans?state=filtered", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	var result struct {
		Scans []domain.ScanHistory `json:"scans"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(result.Scans) != 1 || len(result.Scans[0].Ports) != 1 {
		t.Fatalf("expected one scan with one expanded port observation, got %#v", result.Scans)
	}
	for _, timestamp := range []*time.Time{result.Scans[0].StartedAt, result.Scans[0].FinishedAt} {
		if timestamp == nil {
			t.Fatal("expected scan timestamps in history response")
		}
		if _, offset := timestamp.Zone(); offset != 5*60*60+30*60 {
			t.Errorf("timestamp offset = %d seconds, want IST offset %d", offset, 5*60*60+30*60)
		}
	}
	port := result.Scans[0].Ports[0]
	if port.Port != 8080 || port.State != "filtered" || port.Reason == nil || *port.Reason != "no-response" {
		t.Fatalf("unexpected expanded port in history: %#v", port)
	}
}

// TestGetScansRejectsInvalidLimit verifies a limit of 101 returns 400 with INVALID_LIMIT.
func TestGetScansRejectsInvalidLimit(t *testing.T) {
	repo := &recordingScanRepository{}
	handler := newTestHandler(t, repo, nil, 20, 60)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/targets/history.example/scans?limit=101", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	assertErrorResponse(t, response, http.StatusBadRequest, "INVALID_LIMIT")
}

func newTestHandler(t *testing.T, repo *recordingScanRepository, allowed []string, batchLimit, defaultTimeout int) http.Handler {
	t.Helper()
	scanService, err := service.NewScanService(repo, batchLimit, defaultTimeout, allowed)
	if err != nil {
		t.Fatalf("create scan service: %v", err)
	}
	return NewHandler(scanService, service.NewHistoryService(repo))
}

func assertErrorResponse(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d: %s", response.Code, status, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", response.Header().Get("Content-Type"))
	}
	var result errorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if result.Error.Code != code {
		t.Fatalf("error code = %q, want %q", result.Error.Code, code)
	}
}

type recordingScanRepository struct {
	calls           int
	historyCalls    int
	request         domain.ScanRequest
	jobs            []domain.ScanJob
	history         []domain.ScanHistory
	comparableScans []domain.ScanHistory
	historyTarget   string
	historyLimit    int
}

func (r *recordingScanRepository) CreateScanRequestWithJobs(_ context.Context, request domain.ScanRequest, jobs []domain.ScanJob) (int64, error) {
	r.calls++
	r.request = request
	r.jobs = append([]domain.ScanJob(nil), jobs...)
	return 1, nil
}

func (r *recordingScanRepository) GetScanHistory(_ context.Context, target string, limit int) ([]domain.ScanHistory, error) {
	r.historyCalls++
	r.historyTarget = target
	r.historyLimit = limit
	return r.history, nil
}

func (r *recordingScanRepository) GetLatestComparableScans(_ context.Context, target string) ([]domain.ScanHistory, error) {
	r.historyTarget = target
	return r.comparableScans, nil
}

func timePtr(value time.Time) *time.Time { return &value }
