package model

import "time"

// Result is the single source of truth for every report format.
type Result struct {
	Scan            ScanInfo        `json:"scan"`
	Parameters      map[string]any  `json:"parameters"`
	Targets         []Service       `json:"targets"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Reports         ReportPaths     `json:"reports"`
	Logs            []string        `json:"logs"`
	Notes           []string        `json:"notes,omitempty"`
}

type ScanInfo struct {
	ID            string    `json:"id"`
	Version       string    `json:"version"`
	Status        string    `json:"status"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	Duration      string    `json:"duration"`
	Args          []string  `json:"args"`
	POCExecuted   bool      `json:"poc_executed"`
	POCSkipped    bool      `json:"poc_skipped"`
	POCSkipReason string    `json:"poc_skip_reason,omitempty"`
	POC           POCInfo   `json:"poc"`
	Errors        []string  `json:"errors,omitempty"`
}

type POCInfo struct {
	Engine          string   `json:"engine,omitempty"`
	Executed        bool     `json:"executed"`
	Skipped         bool     `json:"skipped"`
	SkipReason      string   `json:"skip_reason,omitempty"`
	TemplateDir     string   `json:"template_dir,omitempty"`
	TemplateCount   int      `json:"template_count,omitempty"`
	TemplateVersion string   `json:"template_version,omitempty"`
	Targets         int      `json:"targets"`
	Findings        int      `json:"findings"`
	Duration        string   `json:"duration,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	Severity        string   `json:"severity,omitempty"`
	IDs             []string `json:"ids,omitempty"`
	Error           string   `json:"error,omitempty"`
}

type ReportPaths struct {
	HTML     string `json:"html"`
	Markdown string `json:"markdown"`
	JSON     string `json:"json"`
}

type Service struct {
	Host               string   `json:"host"`
	IP                 string   `json:"ip,omitempty"`
	Port               int      `json:"port"`
	Protocol           string   `json:"protocol"`
	Scheme             string   `json:"scheme,omitempty"`
	URL                string   `json:"url,omitempty"`
	Service            string   `json:"service,omitempty"`
	StatusCode         int      `json:"status_code,omitempty"`
	Title              string   `json:"title,omitempty"`
	Server             string   `json:"server,omitempty"`
	TLS                string   `json:"tls,omitempty"`
	ContentType        string   `json:"content_type,omitempty"`
	ContentLength      int64    `json:"content_length,omitempty"`
	Location           string   `json:"location,omitempty"`
	FaviconHash        string   `json:"favicon_hash,omitempty"`
	Technologies       []string `json:"technologies,omitempty"`
	FingerprintSources []string `json:"fingerprint_sources,omitempty"`
	Banner             string   `json:"banner,omitempty"`
	Error              string   `json:"error,omitempty"`
}

type Vulnerability struct {
	Engine           string         `json:"engine"`
	TemplateID       string         `json:"template_id"`
	Name             string         `json:"name"`
	Severity         string         `json:"severity"`
	Target           string         `json:"target"`
	MatchedAt        string         `json:"matched_at,omitempty"`
	MatcherName      string         `json:"matcher_name,omitempty"`
	ExtractorName    string         `json:"extractor_name,omitempty"`
	Type             string         `json:"type,omitempty"`
	Description      string         `json:"description,omitempty"`
	ExtractedResults []string       `json:"extracted_results,omitempty"`
	RequestSummary   string         `json:"request_summary,omitempty"`
	ResponseSummary  string         `json:"response_summary,omitempty"`
	Timestamp        time.Time      `json:"timestamp"`
	Metadata         map[string]any `json:"metadata,omitempty"`
	// Structured classification fields extracted from nuclei's Info block so
	// reports can render them as labeled sections instead of a struct dump.
	Tags        []string `json:"tags,omitempty"`
	References  []string `json:"references,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Impact      string   `json:"impact,omitempty"`
	CVE         []string `json:"cve,omitempty"`
	CWE         []string `json:"cwe,omitempty"`
	CVSSScore   float64  `json:"cvss_score,omitempty"`
	CVSSMetrics string   `json:"cvss_metrics,omitempty"`
	CPE         string   `json:"cpe,omitempty"`
	CURLCommand string   `json:"curl_command,omitempty"`
}
