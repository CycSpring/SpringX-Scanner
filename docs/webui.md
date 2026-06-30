# SpringX WebUI

`springx web` runs a long-running HTTP server that drives `springx scan --jsonl-only` child processes and streams their JSONL events to browsers over Server-Sent Events (SSE). The scanner core is not modified; the WebUI is a thin front over the `springx.events.v1` protocol documented in [events.md](events.md).

## Run

```powershell
.\dist\springx.exe web
# custom address / work directory
.\dist\springx.exe web --addr 127.0.0.1 --port 8849 --work-dir .
```

Then open <http://127.0.0.1:8849>. By default the server listens on `127.0.0.1:8849` (loopback only) and writes reports into the current directory's `reports/` tree — the same location the `scan` subcommand writes to.

Flags:

| Flag | Default | Purpose |
|------|---------|---------|
| `--addr` | `127.0.0.1` | listen address |
| `--port` | `8849` | listen port |
| `--work-dir` | current dir | working directory for scan reports (resolved to an absolute path) |
| `--job-ttl` | `30m` | time-to-live for finished scan jobs; a background reaper removes terminal jobs (and their persisted snapshots) older than this once they have no active SSE subscribers. `0` disables reaping. |

## How it works

```
Browser ──HTTP/SSE──► springx web (net/http server)
                        │  POST /api/scan      → generates job_id + forks `springx scan --jsonl-only`
                        │  GET  /api/events    → SSE: replay cached events + live stream
                        │  POST /api/scan/:id/cancel → Ctrl-Break (Win) / SIGTERM (Unix) → Kill
                        ▼
  child: springx scan --jsonl-only --web --no-browser <flags>
         stdout = JSONL springx.events.v1
         ▼
  bufio.Scanner → json.Unmarshal → event.Event → cache + SSE broadcast
```

Key design points:

- **job_id vs scan_id.** `POST /api/scan` returns a `job_id` immediately so the browser can subscribe before the engine `scan_id` is known (it arrives with the `scan_started` event). The SSE endpoint is keyed on `job_id`; the engine `scan_id` is kept as metadata on the job.
- **JSONL-only seam.** The child runs with `--jsonl-only`, so its stdout is pure JSONL — one `springx.events.v1` event per line. The WebUI never parses human log text.
- **Cache as source of truth.** Each job caches its full event history. New SSE connections replay the cache before streaming live events, so a reconnect never loses terminal events (`scan_completed` / `scan_failed` / `report_written`).
- **Cancellation.** `os.Interrupt` is not deliverable to Windows child processes, so on Windows the child is started in its own process group (`CREATE_NEW_PROCESS_GROUP`) and cancelled with `GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid)` — which the Go runtime maps to `os.Interrupt` inside the child, so `scan.go` finishes with `status:"stopped"` and still emits `report_written`. After a 5s grace window the child is force-killed. On Unix, `SIGTERM` → 5s → `SIGKILL`.
- **Reports.** Reports land in `reports/{html,markdown,data}/` under the work directory. The reports API only reads `reports/data/*.json` by basename and rejects path traversal.
- **Persistence & TTL.** When a job reaches a terminal state, its snapshot (status, scan_id, report paths, full event history) is written to `reports/jobs/<job_id>.json` under the work directory. On restart, `NewScanManager` loads these snapshots so `GET /api/scans` still shows prior history and SSE can replay a past job's cached events. A background reaper (started by `Server.Start`, tuned by `--job-ttl`) removes terminal jobs older than the TTL once they have no active SSE subscribers, deleting both the in-memory entry and the persisted snapshot. `--job-ttl 0` disables reaping.
- **Detail expansion.** The live service and vulnerability tables (and the historical report tables) have expandable rows: click a row to reveal the full fingerprint (TLS, content type/length, location, favicon hash, fingerprint sources, banner) or vulnerability detail (matched path, description, matcher/extractor, extracted results, request/response summaries). The live `vulnerability_found` event carries these fields so the detail is available in real time, not only from the final report JSON.

## HTTP API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | SPA shell (embedded `index.html`) |
| `GET` | `/static/*` | Static assets (`app.css`, `app.js`, embedded) |
| `GET` | `/api/health` | `{"status":"ok"}` liveness probe |
| `POST` | `/api/scan` | Body: JSON scan parameters. Returns `{"job_id":"..."}` |
| `GET` | `/api/scans` | All known scan jobs (newest first) |
| `GET` | `/api/events?id=<job_id>` | SSE stream: cached history replayed, then live events |
| `POST` | `/api/scan/<job_id>/cancel` | Gracefully cancel a running scan |
| `GET` | `/api/reports` | List `reports/data/*.json` with metadata (scan id, started_at, counts) |
| `GET` | `/api/reports/<name>` | Single report JSON (basename only; path traversal rejected) |

### Scan request body

Only functional flags are surfaced; no-op compatibility flags (`--dbs`, `--risk`, `--deep-scan`, ...) are not exposed by the WebUI.

```json
{
  "url": "https://example.com",
  "ip": "",
  "urlfile": "",
  "ipfile": "",
  "ports": "TOP100",
  "threads": 5,
  "done": 10,
  "proxy": "",
  "nopoc": false,
  "nuclei_tags": "",
  "nuclei_severity": "critical,high",
  "nuclei_ids": "",
  "nuclei_template_dir": "",
  "poc_concurrency": 5,
  "gonmap_timeout": 5,
  "temp_dir": ""
}
```

At least one of `url`, `ip`, `urlfile`, `ipfile` is required.

### SSE format

Each event is sent as `data: <json>\n\n`, where `<json>` is the full `springx.events.v1` envelope (see [events.md](events.md)). Clients use the browser `EventSource` API and `JSON.parse(msg.data)`.

## Build

The WebUI is built into the same single binary; no separate frontend toolchain is required. Static assets are embedded with `//go:embed`. The standard build produces the `web` subcommand alongside `scan`:

```powershell
.\build.ps1
.\dist\springx.exe web
```

`go mod tidy` promotes `golang.org/x/sys` (already present as a nuclei transitive dependency) to a direct dependency for the Windows cancellation path; no new modules are downloaded.

## Smoke Tests

The fake-runner unit tests in `internal/web/` run as part of the default `go test ./...` suite and need no external binary. A real-binary integration test is gated behind the `smoke` build tag and exercises the full `springx scan --jsonl-only` child process end to end against a local `httptest` target with the `springx-smoke` nuclei template. The test builds `springx.exe` itself into a temp dir, so no pre-built binary is required.

```powershell
go test -tags smoke -timeout 300s ./internal/web/...
```

It asserts the complete event chain (`scan_started → poc_started → vulnerability_found → poc_completed → scan_completed → report_written`), envelope consistency, the on-disk JSON report, and that the HTML/Markdown siblings exist.
