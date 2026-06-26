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

## Compatibility Flags

`--web` and `--no-browser` are accepted for WebUI compatibility. The CLI core does not open a browser by itself; use `--jsonl-only` or `--log-format jsonl` when a caller needs machine-readable stdout.

Temporary files default to `SPRINGX_TEMP_DIR`, then `D:\Temp` on Windows, then the OS temp directory on other systems. Override with `--temp-dir D:\Temp\springx-run` when needed.
