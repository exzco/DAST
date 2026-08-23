// Package engine provides result aggregation, deduplication, and rate/budget governance.
package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"distributed-scanner/internal/model"
)

var (
	ErrRequestBudgetExceeded  = errors.New("request budget exceeded")
	ErrDurationBudgetExceeded = errors.New("duration budget exceeded")
)

type Aggregator struct {
	mu           sync.Mutex
	findings     map[string]model.Finding
	observations map[string]model.PortObservation
	stats        model.ScanRunStats
}

func NewAggregator() *Aggregator {
	return &Aggregator{
		findings:     make(map[string]model.Finding),
		observations: make(map[string]model.PortObservation),
	}
}

func (a *Aggregator) IngestObservation(obs model.PortObservation) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := fmt.Sprintf("%s:%d", obs.Host, obs.Port)
	existing, exists := a.observations[key]
	if !exists {
		a.observations[key] = obs
		if obs.Status == model.PortStatusOpen {
			a.stats.OpenPorts++
		}
	} else if existing.Status != model.PortStatusOpen && obs.Status == model.PortStatusOpen {
		a.observations[key] = obs
		a.stats.OpenPorts++
	}
}

func (a *Aggregator) IngestFinding(f model.Finding) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if f.StableKey == "" {
		f.StableKey = model.GenerateStableFindingKey(f.TenantID, f.MatchedAt, f.MatchedAt, f.CheckID, f.Parameter, "")
	}

	existing, exists := a.findings[f.StableKey]
	if !exists {
		a.findings[f.StableKey] = f
		a.stats.FindingsCount++
	} else {
		existing.LastSeen = time.Now().UTC()
		for _, ref := range f.EvidenceRefs {
			hasRef := false
			for _, r := range existing.EvidenceRefs {
				if r == ref {
					hasRef = true
					break
				}
			}
			if !hasRef {
				existing.EvidenceRefs = append(existing.EvidenceRefs, ref)
			}
		}
		a.findings[f.StableKey] = existing
	}
}

func (a *Aggregator) GetUniqueFindings() []model.Finding {
	a.mu.Lock()
	defer a.mu.Unlock()

	list := make([]model.Finding, 0, len(a.findings))
	for _, f := range a.findings {
		list = append(list, f)
	}
	return list
}

func (a *Aggregator) GetUniqueObservations() []model.PortObservation {
	a.mu.Lock()
	defer a.mu.Unlock()

	list := make([]model.PortObservation, 0, len(a.observations))
	for _, o := range a.observations {
		list = append(list, o)
	}
	return list
}

func (a *Aggregator) Stats() model.ScanRunStats {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stats
}


type TokenBucketRateLimiter struct {
	mu           sync.Mutex
	rps          float64
	burst        int
	tokens       float64
	lastRefill   time.Time
	hostLimiters map[string]*hostLimiter
}

type hostLimiter struct {
	tokens     float64
	lastRefill time.Time
}

func NewRateLimiter(globalRPS int, burst int) *TokenBucketRateLimiter {
	if globalRPS <= 0 {
		globalRPS = 30
	}
	if burst <= 0 {
		burst = globalRPS
	}
	return &TokenBucketRateLimiter{
		rps:          float64(globalRPS),
		burst:        burst,
		tokens:       float64(burst),
		lastRefill:   time.Now(),
		hostLimiters: make(map[string]*hostLimiter),
	}
}

func (r *TokenBucketRateLimiter) Wait(ctx context.Context, host string) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if r.tryAcquire(host) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (r *TokenBucketRateLimiter) tryAcquire(host string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(r.lastRefill).Seconds()
	r.tokens += elapsed * r.rps
	if r.tokens > float64(r.burst) {
		r.tokens = float64(r.burst)
	}
	r.lastRefill = now

	if r.tokens < 1.0 {
		return false
	}

	if host != "" {
		hl, exists := r.hostLimiters[host]
		if !exists {
			hl = &hostLimiter{tokens: 10.0, lastRefill: now}
			r.hostLimiters[host] = hl
		}
		hostElapsed := now.Sub(hl.lastRefill).Seconds()
		hl.tokens += hostElapsed * 10.0
		if hl.tokens > 10.0 {
			hl.tokens = 10.0
		}
		hl.lastRefill = now

		if hl.tokens < 1.0 {
			return false
		}
		hl.tokens -= 1.0
	}

	r.tokens -= 1.0
	return true
}

type BudgetTracker struct {
	mu           sync.Mutex
	policy       model.BudgetPolicy
	startTime    time.Time
	requestsUsed int64
}

func NewBudgetTracker(pol model.BudgetPolicy) *BudgetTracker {
	return &BudgetTracker{
		policy:    pol,
		startTime: time.Now(),
	}
}

func (b *BudgetTracker) CheckAndRecordRequest() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.policy.MaxDurationMinutes > 0 {
		if time.Since(b.startTime) > time.Duration(b.policy.MaxDurationMinutes)*time.Minute {
			return ErrDurationBudgetExceeded
		}
	}
	if b.policy.MaxRequestsTotal > 0 && b.requestsUsed >= b.policy.MaxRequestsTotal {
		return ErrRequestBudgetExceeded
	}
	b.requestsUsed++
	return nil
}
