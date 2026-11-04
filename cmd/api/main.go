package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nmap-api/internal/api"
	"nmap-api/internal/config"
	"nmap-api/internal/db"
	"nmap-api/internal/nmap"
	"nmap-api/internal/service"
	"nmap-api/internal/worker"
)

func main() {
	if err := run(); err != nil {
		log.Printf("API stopped with error: %v", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	connectCtx, cancelConnect := context.WithTimeout(context.Background(), 10*time.Second)
	database, err := db.OpenDB(connectCtx, cfg)
	cancelConnect()
	if err != nil {
		return fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	defer database.Close()

	repository := db.NewRepository(database)
	scanService, err := service.NewScanService(repository, cfg.MaxBatchSize, cfg.DefaultTimeoutSeconds, cfg.ScanAllowedTargets)
	if err != nil {
		return fmt.Errorf("configure scan service: %w", err)
	}
	nmapRunner, err := nmap.NewRunner("", time.Duration(cfg.DefaultTimeoutSeconds)*time.Second)
	if err != nil {
		return fmt.Errorf("configure Nmap runner: %w", err)
	}
	processor, err := worker.NewProcessor(repository, nmapRunner, time.Duration(cfg.DefaultTimeoutSeconds)*time.Second)
	if err != nil {
		return fmt.Errorf("configure scan processor: %w", err)
	}
	workerPool, err := worker.NewPool(processor, cfg.WorkerCount, worker.DefaultPollTime)
	if err != nil {
		return fmt.Errorf("configure worker pool: %w", err)
	}

	server := &http.Server{
		Addr:              cfg.APIAddr(),
		Handler:           api.NewHandler(scanService),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", server.Addr, err)
	}

	rootCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	workerCtx, cancelWorkers := context.WithCancel(context.Background())
	workerDone := make(chan error, 1)
	go func() {
		workerDone <- workerPool.Run(workerCtx)
	}()

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.Serve(listener)
	}()
	log.Printf("Starting API on %s", server.Addr)

	var serverErr error
	workerStopped := false
	select {
	case <-rootCtx.Done():
	case serverErr = <-serverDone:
		if errors.Is(serverErr, http.ErrServerClosed) {
			serverErr = nil
		}
	case err := <-workerDone:
		workerStopped = true
		if err != nil {
			serverErr = fmt.Errorf("worker pool: %w", err)
		} else {
			serverErr = errors.New("worker pool stopped unexpectedly")
		}
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	shutdownErr := shutdownHTTPServer(shutdownCtx, server, cancelWorkers)
	if shutdownErr != nil {
		_ = server.Close()
	}
	cancelShutdown()
	if !workerStopped {
		if err := <-workerDone; err != nil && serverErr == nil {
			serverErr = fmt.Errorf("worker pool shutdown: %w", err)
		}
	}

	if serverErr != nil {
		return serverErr
	}
	if shutdownErr != nil {
		return fmt.Errorf("shut down HTTP server: %w", shutdownErr)
	}
	return nil
}

func shutdownHTTPServer(ctx context.Context, server *http.Server, cancelWorkers context.CancelFunc) error {
	cancelWorkers()
	return server.Shutdown(ctx)
}
