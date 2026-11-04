package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestShutdownCancelsWorkersBeforeWaitingForHTTPHandlers(t *testing.T) {
	workerCtx, cancelWorkers := context.WithCancel(context.Background())
	defer cancelWorkers()

	handlerStarted := make(chan struct{})
	handlerStopped := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(handlerStarted)
		<-workerCtx.Done()
		close(handlerStopped)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	requestDone := make(chan error, 1)
	go func() {
		response, err := http.Get(server.URL)
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}
		requestDone <- err
	}()
	select {
	case <-handlerStarted:
	case <-time.After(time.Second):
		t.Fatal("HTTP handler did not start")
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), time.Second)
	defer cancelShutdown()
	if err := shutdownHTTPServer(shutdownCtx, server.Config, cancelWorkers); err != nil {
		t.Fatalf("graceful HTTP shutdown: %v", err)
	}
	select {
	case <-handlerStopped:
	case <-time.After(time.Second):
		t.Fatal("handler did not stop after worker cancellation")
	}
	select {
	case err := <-requestDone:
		if err != nil {
			t.Fatalf("HTTP request: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP request did not finish")
	}
}
