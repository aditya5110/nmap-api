package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"nmap-api/internal/nmap"
)

const target = "scanme.nmap.org"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Nmap demo failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	timeout, err := configuredTimeout()
	if err != nil {
		return err
	}

	runner, err := nmap.NewRunner("", timeout)
	if err != nil {
		return fmt.Errorf("configure Nmap runner: %w", err)
	}

	output, err := runner.Run(context.Background(), target)
	if err != nil {
		if diagnostics := strings.TrimSpace(output.Stderr); diagnostics != "" {
			return fmt.Errorf("run Nmap for %s: %w (diagnostics: %s)", target, err, diagnostics)
		}
		return fmt.Errorf("run Nmap for %s: %w", target, err)
	}

	scan, err := nmap.ParseXML(target, output.XML)
	if err != nil {
		return fmt.Errorf("parse Nmap output for %s: %w", target, err)
	}

	printResults(scan)
	return nil
}

func configuredTimeout() (time.Duration, error) {
	const maxTimeoutSeconds = 120

	value := os.Getenv("DEFAULT_TIMEOUT_SECONDS")
	if value == "" {
		return maxTimeoutSeconds * time.Second, nil
	}

	seconds, err := strconv.Atoi(value)
	if err != nil || seconds <= 0 {
		return 0, fmt.Errorf("DEFAULT_TIMEOUT_SECONDS must be a positive integer")
	}
	if seconds > maxTimeoutSeconds {
		seconds = maxTimeoutSeconds
	}

	return time.Duration(seconds) * time.Second, nil
}

func printResults(scan nmap.ScanResult) {
	fmt.Println("========================================")
	fmt.Println("         NMAP SCAN RESULTS")
	fmt.Println("========================================")
	fmt.Printf("\nTarget: %s\n", scan.Target)
	fmt.Println("Status: Completed")

	if scan.StartedAt != nil {
		fmt.Printf("Scan started: %s\n", scan.StartedAt.Format(time.RFC3339))
	}
	if scan.FinishedAt != nil {
		fmt.Printf("Scan finished: %s\n", scan.FinishedAt.Format(time.RFC3339))
	}
	if scan.StartedAt != nil && scan.FinishedAt != nil {
		duration := scan.FinishedAt.Sub(*scan.StartedAt)
		if duration >= 0 {
			fmt.Printf("Scan duration: %s\n", duration)
		}
	}

	for _, host := range scan.Hosts {
		fmt.Println()
		if host.ResolvedIP != nil {
			fmt.Printf("Resolved IP: %s\n", *host.ResolvedIP)
		}
		if host.Status != nil {
			fmt.Printf("Host Status: %s\n", *host.Status)
		}
		if len(host.Ports) == 0 {
			fmt.Println("No ports discovered.")
			continue
		}

		fmt.Printf("%-12s %-14s %s\n", "PORT", "STATE", "SERVICE")
		for _, port := range host.Ports {
			service := ""
			if port.ServiceName != nil {
				service = *port.ServiceName
			}
			fmt.Printf("%-12s %-14s %s\n", fmt.Sprintf("%d/%s", port.Number, port.Protocol), port.State, service)
		}
	}

	fmt.Println("\n========================================")
	fmt.Println("Scan completed.")
	fmt.Println("========================================")
}
