package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/CycSpring/SpringX-Scanner/internal/event"
	"github.com/CycSpring/SpringX-Scanner/internal/model"
)

// validJobIDRE constrains persisted job ids to the shape produced by newJobID
// ("job-<hex>"). This prevents path traversal via a crafted job_id (e.g.
// "..\..\x") when the id is used to build a file path for save/delete.
var validJobIDRE = regexp.MustCompile(`^job-[0-9a-f]+$`)

// validJobID reports whether id is safe to use as a file basename component.
func validJobID(id string) bool {
	return validJobIDRE.MatchString(id)
}

// persistedJob is the on-disk representation of a scan job, written under
// {workDir}/reports/jobs/<job_id>.json when the job reaches a terminal state.
// It carries enough state for GET /api/scans to show history after a restart,
// and (optionally) the full event history for SSE replay of past scans.
type persistedJob struct {
	JobID       string            `json:"job_id"`
	ScanID      string            `json:"scan_id,omitempty"`
	Status      ScanJobStatus     `json:"status"`
	StartedAt   time.Time         `json:"started_at"`
	FinishedAt  time.Time         `json:"finished_at,omitempty"`
	Args        []string          `json:"args,omitempty"`
	ReportPaths model.ReportPaths `json:"reports"`
	Error       string            `json:"error,omitempty"`
	History     []event.Event     `json:"history,omitempty"`
}

// jobsDir is the on-disk home of persisted job snapshots. It is a sibling of
// reports/{html,markdown,data} and is covered by the /reports/ gitignore entry.
func jobsDir(workDir string) string {
	return filepath.Join(workDir, "reports", "jobs")
}

func jobFilePath(workDir, jobID string) string {
	return filepath.Join(jobsDir(workDir), jobID+".json")
}

// saveJob writes a terminal job snapshot to disk. It is best-effort: a write
// failure is returned but the caller logs it and continues — persistence is a
// convenience for restart history, not a correctness requirement.
func saveJob(workDir string, j *ScanJob) error {
	snap := j.snapshot()
	if !validJobID(snap.JobID) {
		return nil // refuse to persist an id we cannot safely turn into a path
	}
	j.mu.Lock()
	rec := persistedJob{
		JobID:       snap.JobID,
		ScanID:      snap.ScanID,
		Status:      snap.Status,
		StartedAt:   snap.StartedAt,
		FinishedAt:  j.finishedAt,
		Args:        j.args,
		ReportPaths: j.reportPaths,
		Error:       snap.Error,
		History:     append([]event.Event(nil), j.history_...),
	}
	j.mu.Unlock()

	dir := jobsDir(workDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(jobFilePath(workDir, rec.JobID), append(data, '\n'), 0o644)
}

// loadJobs reads all persisted job snapshots from {workDir}/reports/jobs/*.json.
// Malformed files and ids that are not safe path basenames are skipped. It
// returns job tombstones suitable for seeding ScanManager.jobs: done is closed,
// proc is nil, hub is a fresh empty hub (so SSE replay of the cached history
// works but no new events arrive).
func loadJobs(workDir string) ([]*ScanJob, error) {
	dir := jobsDir(workDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*ScanJob
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		// The filename must match "<job_id>.json" so a file dropped into the
		// directory cannot trick us into loading an arbitrary id.
		base := e.Name()[:len(e.Name())-len(".json")]
		if !validJobID(base) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var rec persistedJob
		if err := json.Unmarshal(data, &rec); err != nil {
			continue // skip corrupt
		}
		if rec.JobID == "" || rec.JobID != base || !validJobID(rec.JobID) {
			continue // id in file must match the filename and the safe-id shape
		}
		j := &ScanJob{
			id:          rec.JobID,
			startedAt:   rec.StartedAt,
			finishedAt:  rec.FinishedAt,
			args:        rec.Args,
			scanID:      rec.ScanID,
			reportPaths: rec.ReportPaths,
			status:      rec.Status,
			errMsg:      rec.Error,
			history_:    rec.History,
			hub:         newHub(),
			done:        closedChan(),
		}
		out = append(out, j)
	}
	return out, nil
}

// deleteJob removes a persisted job snapshot from disk. An invalid id is a no-op
// so a crafted id can never escape the jobs directory.
func deleteJob(workDir, jobID string) error {
	if !validJobID(jobID) {
		return nil
	}
	err := os.Remove(jobFilePath(workDir, jobID))
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}

// closedChan returns an already-closed channel, used to mark a loaded tombstone
// job's done channel as already finished.
func closedChan() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}
