package main

import (
	"log"
	"net/http"
	"time"

	"nmap-api/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	mux := http.NewServeMux()
	server := &http.Server{
		Addr:              cfg.APIAddr(),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("Starting API on %s", server.Addr)
	log.Printf("Configured database target: %s:%d/%s", cfg.DBHost, cfg.DBPort, cfg.DBName)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
