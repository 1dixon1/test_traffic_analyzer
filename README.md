# Advanced Traffic Analyzer (Test Task)

## Overview

`advanced_traffic_analyzer.py` is a CLI tool that analyzes extended web server access logs with support for filtering and aggregation.

**Log format (one record per line):**
```
<timestamp> <ip_address> <http_method> <url> <status_code> <response_size>
```

Example:
```
1717020800 192.168.1.10 GET /home 200 1500
```

The script is designed to handle large files (up to ~1,000,000 lines) efficiently.

---

## Features

### CLI arguments

- **Positional (required):**
  - `logfile` — path to the log file

- **Optional:**
  - `--method <HTTP_METHOD>` — filter by method (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`)
  - `--status <STATUS_CODE>` — filter by status (`200`) or range (`400-499`)
  - `--start <TIMESTAMP>` — start timestamp (inclusive)
  - `--end <TIMESTAMP>` — end timestamp (inclusive)
  - `--top <N>` — number of IPs in the Top list (default `3`)

### Report outputs

- Total requests (after filters)
- Unique IPs
- Top-N active IPs
- Unique IPs in last 24 hours (from the freshest filtered record)
- Distribution by HTTP methods (%)
- Top-5 requested URLs
- Total transferred bytes (+ human-readable)
- Client errors (4xx) and server errors (5xx)
- Average response size for successful requests (2xx)
- Requests per hour for last 24 hours

---

## Usage

### Run on provided sample file

```bash
python advanced_traffic_analyzer.py sample_access.log
```

### Filter by method

```bash
python advanced_traffic_analyzer.py sample_access.log --method GET
```

### Filter by status range

```bash
python advanced_traffic_analyzer.py sample_access.log --status 400-499
```

### Filter by time range

```bash
python advanced_traffic_analyzer.py sample_access.log --start 1764873600 --end 1764959999
```

### Change Top-N

```bash
python advanced_traffic_analyzer.py sample_access.log --top 10
```

---

## Error handling

- Missing file / unreadable file → prints an error to `stderr` and exits with code `2`
- Malformed line → skipped with `WARNING` to `stderr` (line number + reason)
- Invalid CLI args → handled by `argparse` (or a clear error message for `--status`)

---

## Algorithm & Complexity

The solution uses **two streaming passes** over the file:

1. **Pass 1:** compute all global statistics and the maximum timestamp among filtered records.
2. **Pass 2:** re-scan the file and compute “last 24h” stats using the window:
   `max_ts - 86400 .. max_ts`.

**Time complexity:** `O(n)` (two passes → `O(2n)` still linear)  
**Memory usage:** `O(I + U)` where:
- `I` = number of unique IPs (set + Counter)
- `U` = number of unique URLs (Counter)
- plus small constant counters for methods

This is practical for ~1,000,000 lines.

---

## Possible improvements

- Optional `--json` output mode for integrations
- Optional single-pass “last 24h” when logs are time-sorted (sliding window)
- Optional strict IPv4 validation (currently accepts any token as IP)
- Micro-optimizations (`split(" ", 5)`, faster integer parsing) if needed
