package api

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"

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

func NewHandler(scanService *service.ScanService) http.Handler {
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
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: apiError{
			Code:    "NOT_FOUND",
			Message: "endpoint not found",
		}})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, statusCode int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write JSON response: %v", err)
	}
}
