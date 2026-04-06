# waf_con

Terminal UI dashboard for monitoring ModSecurity WAF (OWASP CRS) running in Docker.

![Go](https://img.shields.io/badge/Go-1.25-blue) ![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **Live Events** — real-time feed of WAF audit log events with severity coloring
- **Top IPs** — aggregated view of source IPs with geolocation (ipinfo.io) and drill-down
- **Top Rules** — most triggered CRS rules with drill-down to see matching requests
- **Status** — engine mode, CRS version, paranoia level, anomaly thresholds, uptime, activity sparkline
- Auto-detects ModSecurity container by name
- Supports both multiplexed and raw Docker log streams

## Install

```bash
./build.sh
```

Installs to `~/.aux/bin/waf_con`.

### Build from source

```bash
go build -o waf_con .
```

## Usage

```bash
waf_con                        # auto-detect "modsecurity" container
waf_con --container mywaf      # specify container name
waf_con --refresh 5            # refresh interval in seconds (default: 2)
waf_con --debug                # dump raw Docker log stream for diagnostics
```

### Navigation

| Key | Action |
|-----|--------|
| `Tab` / `Shift+Tab` | Switch tabs |
| `1` `2` `3` `4` | Jump to tab |
| `j` / `k` / `Up` / `Down` | Scroll |
| `Enter` | Drill-down (Top IPs, Top Rules) |
| `Esc` | Back from drill-down |
| `q` | Quit |

## Configuration

Set `IPINFO_TOKEN` in `~/.aux/.env` for IP geolocation:

```
IPINFO_TOKEN=your_token_here
```

## Requirements

- Docker daemon running with a ModSecurity container (e.g. `owasp/modsecurity-crs:nginx-alpine`)
- `MODSEC_AUDIT_LOG_FORMAT=JSON` and `MODSEC_AUDIT_LOG_TYPE=Serial` in container env

## Architecture

```
waf_con
├── cmd/root.go              # CLI setup, Docker init, TUI launch
└── internal/
    ├── docker/client.go     # Docker SDK: find container, stream logs, inspect, exec
    ├── parser/modsec.go     # ModSecurity JSON audit log parser
    ├── geo/                 # ipinfo.io client + file cache (~/.cache/waf-con/geo.json)
    ├── state/store.go       # Ring buffer (5K events) + lifetime counters
    └── tui/                 # Bubble Tea v2 UI with 4 tabs
```
