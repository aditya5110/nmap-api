package api

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"nmap-api/internal/service"
)

const maxRequestBodyBytes = 1 << 20

type errorResponse struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func NewHandler(scanService *service.ScanService, historyService *service.HistoryService) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/v1/scans", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: apiError{
				Code:    "METHOD_NOT_ALLOWED",
				Message: "only POST is supported for this endpoint",
			}})
			return
		}

		var request service.ScanSubmission
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: apiError{
				Code:    "INVALID_JSON",
				Message: "request body must be valid scan JSON",
			}})
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: apiError{
				Code:    "INVALID_JSON",
				Message: "request body must contain exactly one JSON value",
			}})
			return
		}

		accepted, err := scanService.Submit(r.Context(), request)
		if err != nil {
			var validationErr *service.ValidationError
			if errors.As(err, &validationErr) {
				writeJSON(w, http.StatusBadRequest, errorResponse{Error: apiError{
					Code: validationErr.Code, Message: validationErr.Message,
				}})
				return
			}
			log.Printf("submit scan request: %v", err)
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: apiError{
				Code:    "INTERNAL_ERROR",
				Message: "unable to accept scan request",
			}})
			return
		}

		writeJSON(w, http.StatusAccepted, accepted)
	}))
	mux.Handle("/api/v1/targets/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: apiError{
				Code:    "METHOD_NOT_ALLOWED",
				Message: "only GET is supported for this endpoint",
			}})
			return
		}

		target, action, ok := parseTargetRoute(r.URL.Path)
		if !ok {
			writeJSON(w, http.StatusNotFound, errorResponse{Error: apiError{Code: "NOT_FOUND", Message: "endpoint not found"}})
			return
		}
		switch action {
		case "scans":
			limit, err := parseHistoryLimit(r)
			if err != nil {
				writeValidationError(w, err)
				return
			}
			response, err := historyService.History(r.Context(), target, limit)
			if err != nil {
				writeServiceError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, response)
		case "changes":
			response, err := historyService.Changes(r.Context(), target)
			if err != nil {
				writeServiceError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, response)
		default:
			writeJSON(w, http.StatusNotFound, errorResponse{Error: apiError{Code: "NOT_FOUND", Message: "endpoint not found"}})
		}
	}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: apiError{
			Code:    "NOT_FOUND",
			Message: "endpoint not found",
		}})
	})
	return mux
}

func parseTargetRoute(path string) (target, action string, ok bool) {
	const prefix = "/api/v1/targets/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(parts) != 2 || parts[0] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func parseHistoryLimit(r *http.Request) (int, error) {
	values, present := r.URL.Query()["limit"]
	if !present {
		return service.DefaultHistoryLimit, nil
	}
	if len(values) != 1 {
		return 0, &service.ValidationError{Code: "INVALID_LIMIT", Message: "limit must be specified once"}
	}
	limit, err := strconv.Atoi(values[0])
	if err != nil || limit < 1 || limit > service.MaxHistoryLimit {
		return 0, &service.ValidationError{Code: "INVALID_LIMIT", Message: "limit must be between 1 and 100"}
	}
	return limit, nil
}

func writeServiceError(w http.ResponseWriter, err error) {
	var validationErr *service.ValidationError
	if errors.As(err, &validationErr) {
		writeValidationError(w, validationErr)
		return
	}
	if errors.Is(err, service.ErrNoComparableScans) {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: apiError{
			Code: "NO_COMPARABLE_SCANS", Message: "fewer than two comparable completed scans are available",
		}})
		return
	}
	log.Printf("read scan history: %v", err)
	writeJSON(w, http.StatusInternalServerError, errorResponse{Error: apiError{
		Code: "INTERNAL_ERROR", Message: "unable to retrieve scan data",
	}})
}

func writeValidationError(w http.ResponseWriter, err error) {
	var validationErr *service.ValidationError
	if !errors.As(err, &validationErr) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: apiError{Code: "INVALID_REQUEST", Message: "invalid request"}})
		return
	}
	writeJSON(w, http.StatusBadRequest, errorResponse{Error: apiError{
		Code: validationErr.Code, Message: validationErr.Message,
	}})
}

func writeJSON(w http.ResponseWriter, statusCode int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write JSON response: %v", err)
	}
}
