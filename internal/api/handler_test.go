package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nmap-api/internal/domain"
	"nmap-api/internal/service"
)

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

func newTestHandler(t *testing.T, repo *recordingScanRepository, allowed []string, batchLimit, defaultTimeout int) http.Handler {
	t.Helper()
	scanService, err := service.NewScanService(repo, batchLimit, defaultTimeout, allowed)
	if err != nil {
		t.Fatalf("create scan service: %v", err)
	}
	return NewHandler(scanService)
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
	calls   int
	request domain.ScanRequest
	jobs    []domain.ScanJob
}

func (r *recordingScanRepository) CreateScanRequestWithJobs(_ context.Context, request domain.ScanRequest, jobs []domain.ScanJob) (int64, error) {
	r.calls++
	r.request = request
	r.jobs = append([]domain.ScanJob(nil), jobs...)
	return 1, nil
}
