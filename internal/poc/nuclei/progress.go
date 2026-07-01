package nuclei

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
)

// pocProgress implements nuclei's progress.Progress interface to capture real
// request counters during a scan. nuclei calls Init once it has parsed all
// templates (providing the total request count) and IncrementRequests for each
// HTTP request sent, so Done/Total reflects actual scan progress rather than a
// wall-clock guess. A ticker periodically hands a snapshot to cfg.OnProgress.
type pocProgress struct {
	mu       sync.Mutex
	rules    int64
	total    atomic.Int64
	done     atomic.Int64
	matched  atomic.Int64
	errors   atomic.Int64
	start    time.Time
	cb       func(ProgressStats)
	interval time.Duration
	stopCh   chan struct{}
	stopped  bool
	started  bool // guards Init from starting multiple tickers
}

func newPocProgress(cb func(ProgressStats), interval time.Duration) *pocProgress {
	return &pocProgress{
		cb:       cb,
		interval: interval,
		start:    time.Now(),
		stopCh:   make(chan struct{}),
	}
}

func (p *pocProgress) Init(hostCount int64, rulesCount int, requestCount int64) {
	p.mu.Lock()
	if p.started {
		// Init may be called more than once by some nuclei code paths; only
		// start the ticker on the first call to avoid duplicate goroutines.
		p.mu.Unlock()
		return
	}
	p.started = true
	p.rules = int64(rulesCount)
	p.mu.Unlock()
	p.total.Store(requestCount)
	if requestCount <= 0 {
		// Some template types report 0 total at Init; fall back to rules count so
		// the percentage is not stuck at 0% — it is an approximation.
		p.total.Store(int64(rulesCount))
	}
	p.startTicker()
}

func (p *pocProgress) AddToTotal(delta int64) {
	p.total.Add(delta)
}

func (p *pocProgress) IncrementRequests() {
	p.done.Add(1)
}

func (p *pocProgress) SetRequests(count uint64) {
	p.done.Add(int64(count))
}

func (p *pocProgress) IncrementMatched() {
	p.matched.Add(1)
}

func (p *pocProgress) IncrementErrorsBy(count int64) {
	p.errors.Add(count)
}

func (p *pocProgress) IncrementFailedRequestsBy(count int64) {
	p.done.Add(count)
	p.errors.Add(count)
}

func (p *pocProgress) Stop() {
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return
	}
	p.stopped = true
	close(p.stopCh)
	rules := int(p.rules)
	p.mu.Unlock()
	// Emit a final snapshot so callers see the terminal counters. Read fields
	// without holding mu to avoid a self-deadlock (snapshot also locks mu).
	if p.cb != nil {
		p.cb(ProgressStats{
			Done:   p.done.Load(),
			Total:  p.total.Load(),
			Rules:  rules,
			Found:  p.matched.Load(),
			Errors: p.errors.Load(),
		})
	}
}

func (p *pocProgress) startTicker() {
	go func() {
		ticker := time.NewTicker(p.interval)
		defer ticker.Stop()
		for {
			select {
			case <-p.stopCh:
				return
			case <-ticker.C:
				if p.cb != nil {
					p.cb(p.snapshot())
				}
			}
		}
	}()
}

func (p *pocProgress) snapshot() ProgressStats {
	p.mu.Lock()
	rules := int(p.rules)
	p.mu.Unlock()
	return ProgressStats{
		Done:   p.done.Load(),
		Total:  p.total.Load(),
		Rules:  rules,
		Found:  p.matched.Load(),
		Errors: p.errors.Load(),
	}
}

var _ progress.Progress = (*pocProgress)(nil)
