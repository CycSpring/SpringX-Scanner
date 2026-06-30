package web

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/CycSpring/SpringX-Scanner/internal/event"
	"github.com/CycSpring/SpringX-Scanner/internal/model"
)

// ScanRequest carries the user-facing scan parameters from the API into the
// scan manager. Only functional flags are exposed; no-op compat flags are not
// surfaced by the WebUI.
type ScanRequest struct {
	URL               string `json:"url"`
	IP                string `json:"ip"`
	URLFile           string `json:"urlfile"`
	IPFile            string `json:"ipfile"`
	Ports             string `json:"ports"`
	Threads           int    `json:"threads"`
	DoneMinutes       int    `json:"done"`
	Proxy             string `json:"proxy"`
	NoPOC             bool   `json:"nopoc"`
	NucleiTags        string `json:"nuclei_tags"`
	NucleiSeverity    string `json:"nuclei_severity"`
	NucleiIDs         string `json:"nuclei_ids"`
	NucleiTemplateDir string `json:"nuclei_template_dir"`
	POCConcurrency    int    `json:"poc_concurrency"`
	GonmapTimeout     int    `json:"gonmap_timeout"`
	TempDir           string `json:"temp_dir"`
}

// ScanJobStatus is the lifecycle state of a job.
type ScanJobStatus string

const (
	StatusRunning   ScanJobStatus = "running"
	StatusStopped   ScanJobStatus = "stopped"
	StatusCompleted ScanJobStatus = "completed"
	StatusFailed    ScanJobStatus = "failed"
)

func (s ScanJobStatus) terminal() bool {
	return s == StatusStopped || s == StatusCompleted || s == StatusFailed
}

// childProcess abstracts a scan child process so tests can inject a fake that
// emits a canned JSONL stream without spawning the real springx.exe binary
// (os.Executable inside `go test` returns the test binary, not the scanner).
type childProcess interface {
	Start() error
	Wait() error
	Stdout() io.Reader
	Interrupt() error // graceful: Ctrl-Break on Windows, SIGTERM on Unix
	Kill() error      // forceful
}

// ScanJob is one scan execution, owned by ScanManager. It holds the child
// process, the cached full event history (source of truth for SSE replay),
// the engine scan_id (learned from scan_started), report paths (from
// report_written), and the subscriber hub.
type ScanJob struct {
	id         string
	startedAt  time.Time
	finishedAt time.Time
	args       []string

	mu          sync.Mutex
	proc        childProcess
	cancel      context.CancelFunc
	scanID      string
	reportPaths model.ReportPaths
	status      ScanJobStatus
	errMsg      string
	history_    []event.Event
	hub         *sseHub

	done chan struct{} // closed when the pump goroutine exits
	mgr  *ScanManager
}

func (j *ScanJob) history() []event.Event {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]event.Event, len(j.history_))
	copy(out, j.history_)
	return out
}

func (j *ScanJob) isTerminal() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.status.terminal()
}

// jobSnapshot is the public, lock-protected view of a job for API responses.
type jobSnapshot struct {
	JobID      string        `json:"job_id"`
	ScanID     string        `json:"scan_id,omitempty"`
	Status     ScanJobStatus `json:"status"`
	StartedAt  time.Time     `json:"started_at"`
	ReportJSON string        `json:"report_json,omitempty"`
	Error      string        `json:"error,omitempty"`
}

func (j *ScanJob) snapshot() jobSnapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	return jobSnapshot{
		JobID:      j.id,
		ScanID:     j.scanID,
		Status:     j.status,
		StartedAt:  j.startedAt,
		ReportJSON: j.reportPaths.JSON,
		Error:      j.errMsg,
	}
}

// appendEvent caches an event and broadcasts it to subscribers. Caller must NOT
// hold j.mu.
func (j *ScanJob) appendEvent(ev event.Event) {
	j.mu.Lock()
	j.history_ = append(j.history_, ev)
	if ev.Type == "scan_started" {
		if id, ok := ev.Data["id"].(string); ok && j.scanID == "" {
			j.scanID = id
		}
	}
	if ev.Type == "report_written" {
		j.reportPaths = decodeReportPaths(ev.Data)
	}
	switch ev.Type {
	case "scan_completed":
		if status, _ := ev.Data["status"].(string); status == "stopped" {
			j.status = StatusStopped
		} else {
			j.status = StatusCompleted
		}
		j.finishedAt = time.Now()
	case "scan_failed":
		j.status = StatusFailed
		if ev.Error != "" {
			j.errMsg = ev.Error
		}
		j.finishedAt = time.Now()
	}
	j.mu.Unlock()
	j.hub.broadcast(ev)
}

// CommandBuilder builds the child process. It is injectable so tests can feed a
// fake JSONL stream without needing the real springx.exe binary.
type CommandBuilder func(ctx context.Context, exePath string, args []string) (childProcess, error)

// ScanManagerOptions configures a ScanManager.
type ScanManagerOptions struct {
	ExePath string
	WorkDir string
	Logger  *log.Logger
	Builder CommandBuilder
}

// ScanManager owns all running and recently-finished scan jobs.
type ScanManager struct {
	mu      sync.Mutex
	jobs    map[string]*ScanJob
	exePath string
	workDir string
	log     *log.Logger
	builder CommandBuilder
}

// NewScanManager builds a manager with sensible defaults.
func NewScanManager(opts ScanManagerOptions) *ScanManager {
	if opts.Builder == nil {
		opts.Builder = func(ctx context.Context, exePath string, args []string) (childProcess, error) {
			return newRealChild(ctx, exePath, args, opts.WorkDir), nil
		}
	}
	if opts.Logger == nil {
		opts.Logger = log.New(log.Writer(), "[scanmgr] ", log.LstdFlags|log.Lmsgprefix)
	}
	m := &ScanManager{
		jobs:    map[string]*ScanJob{},
		exePath: opts.ExePath,
		workDir: opts.WorkDir,
		log:     opts.Logger,
		builder: opts.Builder,
	}
	// Seed the job table from disk so GET /api/scans shows history after a
	// restart. Loaded jobs are read-only tombstones (done closed, no proc).
	if existing, err := loadJobs(opts.WorkDir); err == nil {
		for _, j := range existing {
			j.mgr = m
			m.jobs[j.id] = j
		}
	} else {
		opts.Logger.Printf("load persisted jobs: %v", err)
	}
	return m
}

// Start launches a scan child process and returns its job_id immediately. The
// job_id is generated by the WebUI (not the engine scan_id, which is only
// learned once scan_started is emitted); the SSE endpoint is keyed on job_id.
func (m *ScanManager) Start(ctx context.Context, req ScanRequest) (*ScanJob, error) {
	args := buildScanArgs(req)
	jobID := newJobID()
	// A scan must outlive the short HTTP request that created it; cancellation
	// is controlled explicitly through Cancel.
	scanCtx, cancel := context.WithCancel(context.Background())

	proc, err := m.builder(scanCtx, m.exePath, args)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("build scan command: %w", err)
	}

	job := &ScanJob{
		id:        jobID,
		startedAt: time.Now(),
		args:      args,
		proc:      proc,
		cancel:    cancel,
		status:    StatusRunning,
		hub:       newHub(),
		done:      make(chan struct{}),
		mgr:       m,
	}

	m.mu.Lock()
	m.jobs[jobID] = job
	m.mu.Unlock()

	if err := proc.Start(); err != nil {
		cancel()
		m.removeJob(jobID)
		return nil, fmt.Errorf("start scan process: %w", err)
	}

	go m.pump(job)
	return job, nil
}

// pump reads JSONL events from the child stdout, parses them into event.Event,
// appends+broadcasts, then waits for process exit and finalizes the job.
func (m *ScanManager) pump(job *ScanJob) {
	defer close(job.done)

	scanner := bufio.NewScanner(job.proc.Stdout())
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] != '{' {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			m.log.Printf("job %s: skip unparseable line: %v", job.id, err)
			continue
		}
		job.appendEvent(ev)
	}
	if err := scanner.Err(); err != nil {
		m.log.Printf("job %s: stdout read error: %v", job.id, err)
	}

	waitErr := job.proc.Wait()

	job.mu.Lock()
	if !job.status.terminal() {
		// No terminal event arrived (e.g. process killed before emitting one);
		// synthesize a failed terminal event so SSE clients unblock.
		job.status = StatusFailed
		job.finishedAt = time.Now()
		if waitErr != nil {
			job.errMsg = waitErr.Error()
		} else {
			job.errMsg = "scan process exited without a terminal event"
		}
		ev := event.Event{
			Type:  "scan_failed",
			Time:  time.Now(),
			Data:  map[string]any{"id": job.scanID},
			Error: job.errMsg,
		}
		job.history_ = append(job.history_, ev)
		job.mu.Unlock()
		job.hub.broadcast(ev)
	} else {
		job.mu.Unlock()
	}

	// Persist the terminal snapshot so /api/scans survives a restart. Best-effort.
	if job.mgr != nil {
		if err := saveJob(job.mgr.workDir, job); err != nil {
			job.mgr.log.Printf("job %s: persist snapshot: %v", job.id, err)
		}
	}
}

// Cancel gracefully stops a running job. Returns ErrJobNotFound if unknown, or
// ErrJobNotRunning if already terminal.
func (m *ScanManager) Cancel(jobID string) error {
	job := m.Get(jobID)
	if job == nil {
		return ErrJobNotFound
	}
	if job.isTerminal() {
		return ErrJobNotRunning
	}
	if err := job.proc.Interrupt(); err != nil {
		m.log.Printf("job %s: interrupt: %v", jobID, err)
	}
	job.cancel()
	select {
	case <-job.done:
	case <-time.After(cancelGrace + 2*time.Second):
		if err := job.proc.Kill(); err != nil {
			m.log.Printf("job %s: kill after interrupt timeout: %v", jobID, err)
		}
		select {
		case <-job.done:
		case <-time.After(2 * time.Second):
		}
	}
	return nil
}

// StartReaper spawns a background goroutine that periodically removes terminal
// jobs older than ttl when they have no active SSE subscribers. ttl <= 0
// disables reaping. It stops when ctx is cancelled. Called from Server.Start.
func (m *ScanManager) StartReaper(ctx context.Context, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	interval := ttl / 4
	if interval < time.Minute {
		interval = time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.reapExpired(ttl)
			}
		}
	}()
}

// reapExpired removes terminal jobs that have been finished longer than ttl and
// have no active subscribers. It also deletes their persisted snapshots.
func (m *ScanManager) reapExpired(ttl time.Duration) {
	m.mu.Lock()
	candidates := make([]*ScanJob, 0, len(m.jobs))
	for _, j := range m.jobs {
		candidates = append(candidates, j)
	}
	m.mu.Unlock()

	now := time.Now()
	for _, j := range candidates {
		j.mu.Lock()
		terminal := j.status.terminal()
		finished := j.finishedAt
		j.mu.Unlock()
		if !terminal || finished.IsZero() {
			continue
		}
		// Require the pump to have exited: until done is closed, the scan may
		// still emit trailing events (notably report_written after
		// scan_completed). Removing the job earlier could drop those.
		select {
		case <-j.done:
		default:
			continue
		}
		if now.Sub(finished) < ttl {
			continue
		}
		if j.hub.count() > 0 {
			continue // a client is mid-stream; skip this tick
		}
		m.removeJob(j.id)
		if err := deleteJob(m.workDir, j.id); err != nil {
			m.log.Printf("reaper: delete persisted job %s: %v", j.id, err)
		}
	}
}

// Get returns the job for jobID, or nil.
func (m *ScanManager) Get(jobID string) *ScanJob {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.jobs[jobID]
}

// List returns snapshots of all jobs, newest first.
func (m *ScanManager) List() []jobSnapshot {
	m.mu.Lock()
	jobs := make([]*ScanJob, 0, len(m.jobs))
	for _, j := range m.jobs {
		jobs = append(jobs, j)
	}
	m.mu.Unlock()
	sort.Slice(jobs, func(i, j int) bool {
		return jobs[i].startedAt.After(jobs[j].startedAt)
	})
	out := make([]jobSnapshot, len(jobs))
	for i, j := range jobs {
		out[i] = j.snapshot()
	}
	return out
}

func (m *ScanManager) removeJob(jobID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.jobs, jobID)
}

func newJobID() string {
	return fmt.Sprintf("job-%x", time.Now().UnixNano())
}

// buildScanArgs turns a ScanRequest into the `springx scan` argv. --jsonl-only
// guarantees a pure JSONL stdout; --web/--no-browser mark WebUI origin (the
// scanner records them but they are otherwise inert).
func buildScanArgs(req ScanRequest) []string {
	args := []string{"scan", "--jsonl-only", "--web", "--no-browser"}
	addStr := func(flag, v string) {
		if v != "" {
			args = append(args, flag, v)
		}
	}
	addInt := func(flag string, v int) {
		if v > 0 {
			args = append(args, flag, itoa(v))
		}
	}
	addStr("-u", req.URL)
	addStr("-i", req.IP)
	addStr("--urlfile", req.URLFile)
	addStr("--ipfile", req.IPFile)
	addStr("-p", req.Ports)
	addInt("-t", req.Threads)
	addInt("--done", req.DoneMinutes)
	addStr("-x", req.Proxy)
	if req.NoPOC {
		args = append(args, "--nopoc")
	}
	addStr("--nuclei-tags", req.NucleiTags)
	addStr("--nuclei-severity", req.NucleiSeverity)
	addStr("--nuclei-ids", req.NucleiIDs)
	addStr("--nuclei-template-dir", req.NucleiTemplateDir)
	addInt("--poc-concurrency", req.POCConcurrency)
	addInt("--gonmap-timeout", req.GonmapTimeout)
	addStr("--temp-dir", req.TempDir)
	return args
}

func decodeReportPaths(data map[string]any) model.ReportPaths {
	get := func(k string) string {
		if v, ok := data[k].(string); ok {
			return v
		}
		return ""
	}
	return model.ReportPaths{
		HTML:     get("html"),
		Markdown: get("markdown"),
		JSON:     get("json"),
	}
}

func itoa(v int) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b []byte
	for v > 0 {
		b = append([]byte{digits[v%10]}, b...)
		v /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// realChild wraps exec.Cmd to satisfy childProcess. The platform-specific
// process-group setup and graceful interrupt live in cancel_windows.go /
// cancel_unix.go.
type realChild struct {
	cmd    *exec.Cmd
	stdout io.Reader
}

func newRealChild(ctx context.Context, exePath string, args []string, workDir string) *realChild {
	_ = ctx
	cmd := exec.Command(exePath, args...)
	if workDir != "" {
		cmd.Dir = workDir
	}
	configureProcessGroup(cmd)
	return &realChild{cmd: cmd}
}

func (c *realChild) Start() error {
	r, err := c.cmd.StdoutPipe()
	if err != nil {
		return err
	}
	c.stdout = r
	return c.cmd.Start()
}

func (c *realChild) Wait() error       { return c.cmd.Wait() }
func (c *realChild) Stdout() io.Reader { return c.stdout }
func (c *realChild) Interrupt() error  { return interruptProcess(c.cmd) }
func (c *realChild) Kill() error       { return c.cmd.Process.Kill() }
