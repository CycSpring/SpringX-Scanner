package scan

import (
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Version             string
	WorkDir             string
	TargetURL           string
	TargetIP            string
	URLFile             string
	IPFile              string
	Cyber               string
	Spy                 string
	Ports               string
	Proxy               string
	OutName             string
	Web                 bool
	NoBrowser           bool
	NoPing              bool
	NoPOC               bool
	Threads             int
	DoneMinutes         int
	ChanRatio           string
	Platform            string
	Size                int
	GonmapTimeout       int
	NucleiTags          []string
	NucleiSeverity      string
	NucleiIDs           []string
	POCConcurrency      int
	HTTPConcurrency     int
	HTTPTimeoutSec      int
	Engines             string
	TemplateDir         string
	TempDir             string
	LogFormat           string
	RawArgs             []string
	AcceptedCompatFlags map[string]any
}

func (c Config) Timeout() time.Duration {
	// TCP connect timeout. Despite the GonmapTimeout field name (kept for
	// compatibility), this value feeds the TCP dialer used by port scanning.
	seconds := c.GonmapTimeout
	if seconds <= 0 {
		seconds = 5
	}
	return time.Duration(seconds) * time.Second
}

// HTTPTimeout returns the per-request timeout for HTTP probing. It is separate
// from the TCP dial timeout because an HTTP request (header + body + redirects)
// typically needs longer than a TCP connect. Defaults to 10s.
func (c Config) HTTPTimeout() time.Duration {
	seconds := c.HTTPTimeoutSec
	if seconds <= 0 {
		seconds = 10
	}
	return time.Duration(seconds) * time.Second
}

func (c Config) MaxDuration() time.Duration {
	if c.DoneMinutes <= 0 {
		return 0
	}
	return time.Duration(c.DoneMinutes) * time.Minute
}

func (c Config) PortConcurrency() int {
	if c.Threads > 0 {
		return clamp(c.Threads*20, 5, 500)
	}
	ratio := strings.TrimSpace(c.ChanRatio)
	if ratio == "" {
		return 80
	}
	if n, err := strconv.Atoi(ratio); err == nil && n > 0 {
		return clamp(n, 5, 500)
	}
	if f, err := strconv.ParseFloat(ratio, 64); err == nil && f > 0 {
		if f <= 1 {
			return clamp(int(math.Round(100*f)), runtime.NumCPU(), 500)
		}
		return clamp(int(math.Round(f)), 5, 500)
	}
	return 80
}

func (c Config) PocConcurrency() int {
	if c.POCConcurrency > 0 {
		return clamp(c.POCConcurrency, 1, 100)
	}
	return 5
}

// HTTPConcurrency returns the HTTP probe worker count. Defaults to 10, clamped
// to [1, 100]. Independent from the TCP port-scan concurrency (PortConcurrency)
// and the POC concurrency (PocConcurrency).
func (c Config) HttpConcurrency() int {
	if c.HTTPConcurrency > 0 {
		return clamp(c.HTTPConcurrency, 1, 100)
	}
	return 10
}

func (c Config) TargetLimit() int {
	if c.Size <= 0 {
		return 100
	}
	return c.Size
}

func (c Config) Parameters() map[string]any {
	return map[string]any{
		"url":                 c.TargetURL,
		"ip":                  c.TargetIP,
		"urlfile":             c.URLFile,
		"ipfile":              c.IPFile,
		"ports":               c.Ports,
		"proxy":               c.Proxy,
		"outname":             c.OutName,
		"web":                 c.Web,
		"no-browser":          c.NoBrowser,
		"noping":              c.NoPing,
		"nopoc":               c.NoPOC,
		"threads":             c.Threads,
		"done":                c.DoneMinutes,
		"chan":                c.ChanRatio,
		"platform":            c.Platform,
		"size":                c.Size,
		"gonmap-timeout":      c.GonmapTimeout,
		"nuclei-tags":         c.NucleiTags,
		"nuclei-severity":     c.NucleiSeverity,
		"nuclei-ids":          c.NucleiIDs,
		"poc-concurrency":     c.POCConcurrency,
		"http-concurrency":    c.HTTPConcurrency,
		"http-timeout":        c.HTTPTimeoutSec,
		"engines":             c.Engines,
		"nuclei-template-dir": c.TemplateDir,
		"temp-dir":            c.GetTempDir(),
		"log-format":          c.NormalizedLogFormat(),
		"compat":              c.AcceptedCompatFlags,
	}
}

func (c Config) NormalizedLogFormat() string {
	switch strings.ToLower(strings.TrimSpace(c.LogFormat)) {
	case "", "mixed":
		return "mixed"
	case "jsonl":
		return "jsonl"
	default:
		return strings.ToLower(strings.TrimSpace(c.LogFormat))
	}
}

func (c Config) JSONLOnly() bool {
	return c.NormalizedLogFormat() == "jsonl"
}

func (c Config) GetTempDir() string {
	if c.TempDir != "" {
		return c.TempDir
	}
	// Respect SPRINGX_TEMP_DIR environment variable first.
	if td := os.Getenv("SPRINGX_TEMP_DIR"); td != "" {
		return td
	}
	// Windows defaults to D:\Temp (user preference for C: drive space).
	if runtime.GOOS == "windows" {
		return "D:\\Temp"
	}
	// Otherwise use OS default temp dir.
	return os.TempDir()
}

func clamp(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}
