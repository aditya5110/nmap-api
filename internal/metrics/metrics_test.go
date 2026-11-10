package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nmap-api/internal/api"
)

// TestHTTPHandlerRecordsBoundedRouteMetrics verifies method, route template, status, duration, and in-flight metrics without exposing the target.
func TestHTTPHandlerRecordsBoundedRouteMetrics(t *testing.T) {
	metrics := New()
	handlerStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	application := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(handlerStarted)
		<-releaseHandler
		w.WriteHeader(http.StatusAccepted)
	})
	handler := metrics.HTTPHandler(application)

	requestDone := make(chan struct{})
	go func() {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/targets/192.168.64.2/scans?state=all", nil)
		handler.ServeHTTP(httptest.NewRecorder(), request)
		close(requestDone)
	}()
	<-handlerStarted

	inFlight := scrapeMetrics(t, handler)
	if !strings.Contains(inFlight, `http_requests_in_flight{method="GET",route="/api/v1/targets/{target}/scans"} 1`) {
		t.Fatalf("expected one in-flight request with a normalized route, metrics:\n%s", inFlight)
	}
	if strings.Contains(inFlight, "192.168.64.2") {
		t.Fatalf("metrics exposed the request target:\n%s", inFlight)
	}
	close(releaseHandler)
	<-requestDone

	output := scrapeMetrics(t, handler)
	if !strings.Contains(output, `http_requests_total{method="GET",route="/api/v1/targets/{target}/scans",status_code="202"} 1`) {
		t.Fatalf("expected request counter with normalized labels and status, metrics:\n%s", output)
	}
	if !strings.Contains(output, `http_request_duration_seconds_count{method="GET",route="/api/v1/targets/{target}/scans",status_code="202"} 1`) {
		t.Fatalf("expected request duration observation, metrics:\n%s", output)
	}
	if !strings.Contains(output, `http_requests_in_flight{method="GET",route="/api/v1/targets/{target}/scans"} 0`) {
		t.Fatalf("expected in-flight gauge to return to zero, metrics:\n%s", output)
	}
	if strings.Contains(output, `route="/metrics"`) || strings.Contains(output, "192.168.64.2") {
		t.Fatalf("metrics scrape or target value appeared in application labels:\n%s", output)
	}
}

// TestMetricsEndpointDoesNotChangeAPIRouteBehavior verifies /metrics is served separately and the existing API method error remains unchanged.
func TestMetricsEndpointDoesNotChangeAPIRouteBehavior(t *testing.T) {
	handler := New().HTTPHandler(api.NewHandler(nil, nil))

	apiResponse := httptest.NewRecorder()
	handler.ServeHTTP(apiResponse, httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil))
	if apiResponse.Code != http.StatusMethodNotAllowed || apiResponse.Header().Get("Content-Type") != "application/json" || !strings.Contains(apiResponse.Body.String(), `"code":"METHOD_NOT_ALLOWED"`) {
		t.Fatalf("existing API response changed: status=%d content-type=%q body=%q", apiResponse.Code, apiResponse.Header().Get("Content-Type"), apiResponse.Body.String())
	}

	metricsResponse := httptest.NewRecorder()
	handler.ServeHTTP(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metricsResponse.Code != http.StatusOK || !strings.Contains(metricsResponse.Body.String(), `http_requests_total{method="GET",route="/api/v1/scans",status_code="405"} 1`) {
		t.Fatalf("GET /metrics response = %d %q", metricsResponse.Code, metricsResponse.Body.String())
	}
	if strings.Contains(metricsResponse.Body.String(), `route="/metrics"`) {
		t.Fatalf("metrics scrape was included in application HTTP metrics: %q", metricsResponse.Body.String())
	}
}

func scrapeMetrics(t *testing.T, handler http.Handler) string {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /metrics status = %d, want %d", response.Code, http.StatusOK)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read metrics response: %v", err)
	}
	return string(body)
}
