package worker

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"nmap-api/internal/db"
)

const (
	LeaseDuration           = 150 * time.Second
	DefaultPollTime         = 250 * time.Millisecond
	DefaultRecoveryInterval = 15 * time.Second
)

type Pool struct {
	processor        *Processor
	workerCount      int
	pollInterval     time.Duration
	recoveryInterval time.Duration
}

func NewPool(processor *Processor, workerCount int, pollInterval time.Duration) (*Pool, error) {
	if processor == nil {
		return nil, errors.New("worker processor is required")
	}
	if workerCount <= 0 {
		return nil, errors.New("worker count must be greater than zero")
	}
	if pollInterval <= 0 {
		pollInterval = DefaultPollTime
	}
	if LeaseDuration <= MaxScanTimeout {
		return nil, errors.New("worker lease duration must exceed the maximum scan timeout")
	}
	return &Pool{
		processor:        processor,
		workerCount:      workerCount,
		pollInterval:     pollInterval,
		recoveryInterval: DefaultRecoveryInterval,
	}, nil
}

// Run starts a fixed number of workers and waits for all of them to stop.
func (p *Pool) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("worker pool context must not be nil")
	}

	var workers sync.WaitGroup
	workers.Add(p.workerCount + 1)
	go func() {
		defer workers.Done()
		p.runRecovery(ctx)
	}()
	for i := 0; i < p.workerCount; i++ {
		go func(workerID int) {
			defer workers.Done()
			p.runWorker(ctx, workerID)
		}(i + 1)
	}
	workers.Wait()
	return nil
}

func (p *Pool) runRecovery(ctx context.Context) {
	ticker := time.NewTicker(p.recoveryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := p.processor.repository.RecoverExpiredJobs(ctx); err != nil && ctx.Err() == nil {
				log.Printf("recover expired jobs: %v", err)
			}
		}
	}
}

func (p *Pool) runWorker(ctx context.Context, workerID int) {
	for ctx.Err() == nil {
		job, err := p.processor.repository.ClaimNextJob(ctx, LeaseDuration)
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("worker %d: claim job: %v", workerID, err)
			}
			if !wait(ctx, p.pollInterval) {
				return
			}
			continue
		}
		if job == nil {
			if !wait(ctx, p.pollInterval) {
				return
			}
			continue
		}

		if err := p.processor.process(ctx, *job); err != nil && !errors.Is(err, db.ErrClaimLost) && ctx.Err() == nil {
			log.Printf("worker %d: %v", workerID, err)
		}
	}
}

func wait(ctx context.Context, interval time.Duration) bool {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return ctx.Err() == nil
	}
}
