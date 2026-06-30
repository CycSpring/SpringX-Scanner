# SpringX Scanner

SpringX Scanner is the self-owned SpringX scanning core MVP. It provides a WebUI-compatible `springx.exe scan ...` command, performs target parsing, TCP port probing, HTTP service detection, optional Nuclei SDK scanning, and renders HTML, Markdown, and JSON reports from one structured result model.

## MVP Scope

- URL, URL file, IP/host, IP file, and CIDR targets.
- Port presets and custom ports/ranges.
- HTTP/HTTPS probing with status, title, server, TLS, and lightweight technology hints.
- Nuclei v3 SDK execution against `pocs/nuclei`.
- Reports:
  - `reports/html/SpringX-Scan-YYYYMMDD-HHMMSS.html`
  - `reports/markdown/SpringX-Scan-YYYYMMDD-HHMMSS.md`
  - `reports/data/SpringX-Scan-YYYYMMDD-HHMMSS.json`
- Human-readable logs plus JSONL structured events on stdout.

The MVP intentionally does not implement FOFA/Hunter, Xray, GoPOC, YamlPOC, weak password cracking, screenshot capture, keylogger, credential recovery, WiFi password recovery, or intranet spy workflows.

## Build

```powershell
$env:GOPROXY='https://goproxy.cn,direct'
$env:GOMODCACHE='D:\Temp\go-mod-cache'
$env:GOCACHE='D:\Temp\go-build-cache'
$env:GOTOOLCHAIN='auto'
go build -o dist\springx.exe .
```

Or use the pinned Windows build script:

```powershell
.\build.ps1
.\build.ps1 -Version v0.2.0
```

The script runs `go test ./...` before building, writes Go caches under `D:\Temp`, and injects version/build time into `springx.exe --version`.

## Smoke Tests

```powershell
.\dist\springx.exe --help
.\dist\springx.exe scan -u https://example.com --web --no-browser --outname SpringX --nopoc
.\dist\springx.exe scan -i 127.0.0.1 -p 80,443 -t 3 --nopoc
.\dist\springx.exe scan --urlfile urls.txt --nuclei-severity critical,high
.\dist\springx.exe scan -u http://127.0.0.1:8080 --nuclei-template-dir .\testdata\nuclei --nuclei-ids springx-smoke
```

By default, Nuclei templates are loaded from `pocs\nuclei` under the process working directory. If the directory is missing, scanning still completes and the reports explicitly show that POC execution was skipped.

## Scan Tuning

HTTP probing runs concurrently over a shared keep-alive client. Use these flags to tune real-network behavior:

| Flag | Default | Purpose |
|------|---------|---------|
| `--http-concurrency` | `10` | HTTP probe worker count (clamped to 1–100). Raise for many `--urlfile` targets. |
| `--http-timeout` | `10` | Per-request HTTP timeout in seconds (header + body + redirects). Separate from the TCP dial timeout. |
| `--gonmap-timeout` | `5` | TCP connect timeout in seconds (port scanning / `isPortOpen`). |
| `-t/--threads` | `5` | Drives TCP port-scan concurrency (`threads×20`, clamped 5–500). |

Probe resilience: a transient HTTP network error (timeout, connection refused, EOF) is retried once; failed probes still emit `service_detected` with `status_code: 0` and an `error` field and appear in the report so unreachable targets are visible rather than silently dropped. Failed probes are not fed to Nuclei.

## WebUI

`springx web` runs a long-running HTTP server that drives `springx scan --jsonl-only` child processes and streams their JSONL events to the browser over Server-Sent Events. The scanner core is unchanged; the WebUI consumes the `springx.events.v1` protocol.

```powershell
.\dist\springx.exe web
# custom address / work directory
.\dist\springx.exe web --addr 127.0.0.1 --port 8849 --work-dir .
```

Then open <http://127.0.0.1:8849>. The WebUI provides: a scan form (functional flags only), real-time progress via SSE, live service/vulnerability tables, a history of reports under `reports/data/`, and scan cancellation. See [docs/webui.md](docs/webui.md) for the full HTTP API and design notes.

## Compatibility Flags

`--web` and `--no-browser` are accepted for WebUI compatibility. The CLI core does not open a browser by itself; the `springx web` server sets them when it spawns scan child processes to mark their WebUI origin. Use `--jsonl-only` or `--log-format jsonl` when a caller needs machine-readable stdout.

Temporary files default to `SPRINGX_TEMP_DIR`, then `D:\Temp` on Windows, then the OS temp directory on other systems. Override with `--temp-dir D:\Temp\springx-run` when needed.
