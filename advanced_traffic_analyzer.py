#!/usr/bin/env python3
"""
advanced_traffic_analyzer.py

Traffic log analyzer for extended web server access logs.

Log line format:
    <timestamp> <ip_address> <http_method> <url> <status_code> <response_size>

Example:
    1717020800 192.168.1.10 GET /home 200 1500

Design notes:
- Streaming parsing (line-by-line) to support very large files.
- Two-pass approach to compute "last 24h from freshest record" precisely.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple


ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
SECONDS_IN_HOUR = 3600
SECONDS_IN_DAY = 86400


@dataclass(frozen=True)
class Filters:
    """
    Parsed filters applied to records during analysis.

    All filters are inclusive:
    - start_ts: keep records with ts >= start_ts
    - end_ts: keep records with ts <= end_ts
    - status_min/status_max: keep records with status in [min, max]
    - method: keep records where method == Filters.method
    """

    method: Optional[str]
    status_min: Optional[int]
    status_max: Optional[int]
    start_ts: Optional[int]
    end_ts: Optional[int]

    def match(self, ts: int, method: str, status: int) -> bool:
        """
        Return True if a record (ts, method, status) passes all filters.

        Args:
            ts: Unix timestamp (int)
            method: HTTP method string
            status: HTTP status code (int)

        Returns:
            bool: True if the record passes, otherwise False.
        """
        if self.method is not None and method != self.method:
            return False

        if self.start_ts is not None and ts < self.start_ts:
            return False

        if self.end_ts is not None and ts > self.end_ts:
            return False

        if self.status_min is not None and status < self.status_min:
            return False

        if self.status_max is not None and status > self.status_max:
            return False

        return True


@dataclass
class Pass1Stats:
    """
    Aggregations computed during the first pass over the file (after filters).

    Pass 1 is used to compute:
    - global counters (IPs, methods, URLs)
    - total bytes and error counts
    - max timestamp (to define the last-24h window)
    """

    total_requests: int = 0
    unique_ips: set[str] = field(default_factory=set)

    ip_counts: Counter[str] = field(default_factory=Counter)
    method_counts: Counter[str] = field(default_factory=Counter)
    url_counts: Counter[str] = field(default_factory=Counter)

    total_bytes: int = 0

    count_2xx: int = 0
    count_4xx: int = 0
    count_5xx: int = 0
    bytes_2xx_sum: int = 0

    max_ts: Optional[int] = None


@dataclass
class Last24hStats:
    """
    Aggregations computed during the second pass, limited to the last 24 hours.

    "Last 24 hours" is defined relative to the freshest filtered record:
        [max_ts - 86400, max_ts]
    """

    unique_ips_24h: int = 0
    requests_per_hour: Dict[int, int] = field(default_factory=dict)  # hour_ts -> count


def eprint(*args: object) -> None:
    """
    Print to stderr.

    Args:
        *args: any printable objects.
    """
    print(*args, file=sys.stderr)


def human_bytes(num: int) -> str:
    """
    Convert byte count to a human-readable string.

    Args:
        num: number of bytes

    Returns:
        A string like "274.73 KB"
    """
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(num)

    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024.0

    return f"{num} B"


def parse_status_filter(value: str) -> Tuple[int, int]:
    """
    Parse --status filter which can be a single status code or a range.

    Accepted forms:
        "200"
        "400-499"

    Args:
        value: raw CLI string

    Returns:
        (min_status, max_status)

    Raises:
        argparse.ArgumentTypeError: on invalid format.
    """
    if "-" in value:
        left, right = value.split("-", 1)
        if not left.isdigit() or not right.isdigit():
            raise argparse.ArgumentTypeError("Status range must look like 400-499")
        a = int(left)
        b = int(right)
        if a > b:
            raise argparse.ArgumentTypeError("Status range start must be <= end")
        return a, b

    if not value.isdigit():
        raise argparse.ArgumentTypeError("Status must be an integer or range like 400-499")

    s = int(value)
    return s, s


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """
    Parse and validate command-line arguments.

    Args:
        argv: optional argv list for testing (defaults to sys.argv)

    Returns:
        argparse.Namespace with parsed args.
    """
    parser = argparse.ArgumentParser(
        prog="advanced_traffic_analyzer.py",
        description="Analyze extended web server access logs with filtering and aggregation.",
    )

    # Required: input file.
    parser.add_argument("logfile", help="Path to access log file")

    # Optional: filters and controls.
    parser.add_argument("--method", choices=sorted(ALLOWED_METHODS), help="Filter by HTTP method")
    parser.add_argument("--status", type=parse_status_filter, help="Filter by status code (e.g. 200 or 400-499)")
    parser.add_argument("--start", type=int, help="Start timestamp (inclusive)")
    parser.add_argument("--end", type=int, help="End timestamp (inclusive)")
    parser.add_argument("--top", type=int, default=3, help="Top-N IPs (default: 3)")

    args = parser.parse_args(argv)

    # Validate derived constraints that argparse doesn't cover directly.
    if args.top <= 0:
        parser.error("--top must be a positive integer")

    if args.start is not None and args.end is not None and args.start > args.end:
        parser.error("--start must be <= --end")

    return args


def validate_file_readable(path: Path) -> None:
    """
    Validate that the given path exists, is a file, and is readable.

    Args:
        path: filesystem path

    Raises:
        FileNotFoundError: if it doesn't exist
        IsADirectoryError: if it's not a file
        PermissionError: if unreadable
        OSError: on other open failures
    """
    if not path.exists():
        raise FileNotFoundError(str(path))

    if not path.is_file():
        raise IsADirectoryError(str(path))

    # Try opening to confirm permissions and readability.
    with path.open("r", encoding="utf-8", errors="replace"):
        pass


def iter_filtered_records(
    path: Path,
    filters: Filters,
    *,
    warn: bool = True,
) -> Iterable[Tuple[int, str, str, str, int, int]]:
    """
    Stream-parse and yield records that match the filters.

    Malformed lines are skipped. If warn=True, prints warnings to stderr.

    Args:
        path: input log file path
        filters: Filters object
        warn: whether to print warnings for malformed lines

    Yields:
        Tuples of:
            (timestamp, ip, method, url, status_code, response_size)
    """
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            # Expected 6 fields.
            parts = line.split()
            if len(parts) != 6:
                if warn:
                    eprint(
                        f"WARNING: malformed line {lineno}: expected 6 fields, "
                        f"got {len(parts)} -> {line!r}"
                    )
                continue

            ts_s, ip, method, url, status_s, size_s = parts

            # Validate numeric fields.
            if not ts_s.isdigit() or not status_s.isdigit() or not size_s.isdigit():
                if warn:
                    eprint(f"WARNING: malformed line {lineno}: non-integer numeric field -> {line!r}")
                continue

            ts = int(ts_s)
            status = int(status_s)
            size = int(size_s)

            # Validate method.
            if method not in ALLOWED_METHODS:
                if warn:
                    eprint(f"WARNING: malformed line {lineno}: unknown method {method!r} -> {line!r}")
                continue

            # Apply filters.
            if not filters.match(ts, method, status):
                continue

            yield ts, ip, method, url, status, size


def pass1(path: Path, filters: Filters) -> Pass1Stats:
    """
    First pass:
    Compute global aggregates and the freshest timestamp among filtered records.

    Args:
        path: input log file
        filters: Filters object

    Returns:
        Pass1Stats with aggregated metrics.
    """
    stats = Pass1Stats()

    for ts, ip, method, url, status, size in iter_filtered_records(path, filters, warn=True):
        stats.total_requests += 1

        # IP stats.
        stats.unique_ips.add(ip)
        stats.ip_counts[ip] += 1

        # Method and URL stats.
        stats.method_counts[method] += 1
        stats.url_counts[url] += 1

        # Volume stats.
        stats.total_bytes += size

        # Status-class counts.
        if 200 <= status <= 299:
            stats.count_2xx += 1
            stats.bytes_2xx_sum += size
        elif 400 <= status <= 499:
            stats.count_4xx += 1
        elif 500 <= status <= 599:
            stats.count_5xx += 1

        # Track freshest timestamp.
        if stats.max_ts is None or ts > stats.max_ts:
            stats.max_ts = ts

    return stats


def pass2_last24h(path: Path, filters: Filters, max_ts: Optional[int]) -> Last24hStats:
    """
    Second pass:
    Compute metrics for the last 24 hours relative to max_ts.

    This is a second pass (re-scan) to avoid storing all timestamps in memory.

    Args:
        path: input log file
        filters: Filters object
        max_ts: freshest timestamp from pass1 (after filters)

    Returns:
        Last24hStats for the last 24 hours.
    """
    out = Last24hStats()
    if max_ts is None:
        return out

    window_start = max_ts - SECONDS_IN_DAY
    ips_24h: set[str] = set()

    # warn=False to avoid duplicating malformed-line warnings from pass1.
    for ts, ip, method, url, status, size in iter_filtered_records(path, filters, warn=False):
        if ts < window_start or ts > max_ts:
            continue

        ips_24h.add(ip)

        # Bucket by hour boundary.
        hour_ts = (ts // SECONDS_IN_HOUR) * SECONDS_IN_HOUR
        out.requests_per_hour[hour_ts] = out.requests_per_hour.get(hour_ts, 0) + 1

    out.unique_ips_24h = len(ips_24h)
    return out


def format_time_range(filters: Filters) -> str:
    """
    Render time filter settings for the report.

    Args:
        filters: Filters object

    Returns:
        "all time" or "<start> - <end>" with "..." for open-ended.
    """
    if filters.start_ts is None and filters.end_ts is None:
        return "all time"

    start = str(filters.start_ts) if filters.start_ts is not None else "..."
    end = str(filters.end_ts) if filters.end_ts is not None else "..."
    return f"{start} - {end}"


def format_status_filter(filters: Filters) -> str:
    """
    Render status filter settings for the report.

    Args:
        filters: Filters object

    Returns:
        "all statuses" or "200" or "400-499"
    """
    if filters.status_min is None and filters.status_max is None:
        return "all statuses"

    if filters.status_min == filters.status_max:
        return str(filters.status_min)

    return f"{filters.status_min}-{filters.status_max}"


def format_method_filter(filters: Filters) -> str:
    """
    Render HTTP method filter setting for the report.

    Args:
        filters: Filters object

    Returns:
        the method string or "all methods"
    """
    return filters.method if filters.method is not None else "all methods"


def hour_label(hour_ts: int) -> str:
    """
    Convert an hour bucket Unix timestamp to a readable label.

    Args:
        hour_ts: Unix timestamp rounded down to an hour boundary.

    Returns:
        A string like "2026-02-05 11:00Z (1738753200)"
    """
    dt = datetime.fromtimestamp(hour_ts, tz=timezone.utc)
    return f"{dt.strftime('%Y-%m-%d %H:00Z')} ({hour_ts})"


def print_report(filters: Filters, top_n: int, s1: Pass1Stats, s24: Last24hStats) -> None:
    """
    Print the full report to stdout in the required structured format.

    Args:
        filters: Filters used for analysis
        top_n: Top-N value for active IP section
        s1: Pass1Stats (global aggregates)
        s24: Last24hStats (last-24h aggregates)
    """
    print("====== TRAFFIC ANALYSIS REPORT ======")
    print("Filter settings:")
    print(f" - Time range: {format_time_range(filters)}")
    print(f" - Method filter: {format_method_filter(filters)}")
    print(f" - Status filter: {format_status_filter(filters)}")
    print()

    print("Basic statistics:")
    print(f" Total requests: {s1.total_requests}")
    print(f" Unique IPs: {len(s1.unique_ips)}")
    print(f" Total data transferred: {s1.total_bytes} bytes ({human_bytes(s1.total_bytes)})")
    print()

    print("Request distribution:")
    if s1.total_requests == 0:
        print(" (no data)")
    else:
        # Print all methods (including 0.0%) for strict/consistent output.
        for method in sorted(ALLOWED_METHODS):
            c = s1.method_counts.get(method, 0)
            pct = (c / s1.total_requests) * 100.0
            print(f" - {method}: {pct:.1f}%")
    print()

    print("Performance metrics:")
    print(f" - Successful requests (2xx): {s1.count_2xx}")
    print(f" - Client errors (4xx): {s1.count_4xx}")
    print(f" - Server errors (5xx): {s1.count_5xx}")
    avg_2xx = (s1.bytes_2xx_sum // s1.count_2xx) if s1.count_2xx > 0 else 0
    print(f" - Average response size (2xx): {avg_2xx} bytes")
    print()

    print(f"Top {top_n} active IPs:")
    if s1.total_requests == 0:
        print(" (no data)")
    else:
        for i, (ip, c) in enumerate(s1.ip_counts.most_common(top_n), start=1):
            print(f" {i}. {ip}: {c} requests")
    print()

    print("Top 5 requested URLs:")
    if s1.total_requests == 0:
        print(" (no data)")
    else:
        for i, (url, c) in enumerate(s1.url_counts.most_common(5), start=1):
            print(f" {i}. {url}: {c}")
    print()

    print("Recent activity (last 24h):")
    print(f" - Unique IPs: {s24.unique_ips_24h}")

    if not s24.requests_per_hour:
        print(" - Requests per hour (last 24h): []")
    else:
        items = sorted(s24.requests_per_hour.items())
        rendered = ", ".join(f"{hour_label(hour)}: {count}" for hour, count in items)
        print(f" - Requests per hour (last 24h): [{rendered}]")
    print()


def main(argv: Optional[list[str]] = None) -> int:
    """
    Program entrypoint (callable for tests).

    Steps:
    - parse CLI args
    - validate file
    - build Filters
    - pass1 aggregates + max_ts
    - pass2 last-24h aggregates
    - print report

    Args:
        argv: optional argv list for testing

    Returns:
        Process exit code (0 = ok, 2 = error)
    """
    args = parse_args(argv)
    path = Path(args.logfile)

    # Build status bounds from parsed --status tuple.
    if args.status is None:
        status_min = None
        status_max = None
    else:
        status_min, status_max = args.status

    filters = Filters(
        method=args.method,
        status_min=status_min,
        status_max=status_max,
        start_ts=args.start,
        end_ts=args.end,
    )

    # Validate file existence and readability.
    try:
        validate_file_readable(path)
    except FileNotFoundError:
        eprint(f"ERROR: file not found: {path}")
        return 2
    except IsADirectoryError:
        eprint(f"ERROR: not a file: {path}")
        return 2
    except PermissionError:
        eprint(f"ERROR: no permission to read file: {path}")
        return 2
    except OSError as ex:
        eprint(f"ERROR: cannot open file: {path} ({ex})")
        return 2

    # Run analysis.
    s1 = pass1(path, filters)
    s24 = pass2_last24h(path, filters, s1.max_ts)

    # Print report.
    print_report(filters, args.top, s1, s24)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
