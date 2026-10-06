#!/usr/bin/env python3
"""Security Log Analyzer for SSH authentication logs (syslog / auth.log format).

Detects brute-force bursts, username enumeration, and successful logins that
follow failed attempts. Standard library only.

Usage:
    python log_analyzer.py sample_auth.log
    python log_analyzer.py /var/log/auth.log --threshold 5 --window 10 --json
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

LINE = re.compile(r"^(?P<ts>\w{3}\s+\d+\s+[\d:]{8})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)$")
FAILED = re.compile(r"Failed \w+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\da-fA-F:.]+) port")
INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[\da-fA-F:.]+)")
ACCEPTED = re.compile(r"Accepted \w+ for (?P<user>\S+) from (?P<ip>[\da-fA-F:.]+) port")


@dataclass
class Event:
    time: datetime
    kind: str  # failed | accepted
    user: str
    ip: str


@dataclass
class Alert:
    severity: str
    type: str
    ip: str
    detail: str
    first_seen: str
    last_seen: str


@dataclass
class Report:
    lines: int = 0
    parsed: int = 0
    failed: int = 0
    accepted: int = 0
    top_ips: list = field(default_factory=list)
    top_users: list = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)


def parse_log(path: str, year: int) -> tuple[list[Event], int]:
    events: list[Event] = []
    total = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            total += 1
            m = LINE.match(raw.rstrip("\n"))
            if not m:
                continue
            try:
                ts = datetime.strptime(f"{year} {' '.join(m['ts'].split())}", "%Y %b %d %H:%M:%S")
            except ValueError:
                continue
            msg = m["msg"]
            if (f := FAILED.search(msg)) or (f := INVALID.search(msg)):
                events.append(Event(ts, "failed", f["user"], f["ip"]))
            elif (a := ACCEPTED.search(msg)):
                events.append(Event(ts, "accepted", a["user"], a["ip"]))
    return events, total


def detect_bursts(times: list[datetime], threshold: int, window: timedelta):
    """Sliding window: return (first, last, count) of the densest burst, or None."""
    best, left = None, 0
    for right, t in enumerate(times):
        while t - times[left] > window:
            left += 1
        count = right - left + 1
        if count >= threshold and (best is None or count > best[2]):
            best = (times[left], t, count)
    return best


def analyze(events: list[Event], total_lines: int, threshold: int,
            window_min: int, user_threshold: int) -> Report:
    rep = Report(lines=total_lines, parsed=len(events))
    failed_by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in sorted(events, key=lambda e: e.time):
        if e.kind == "failed":
            failed_by_ip[e.ip].append(e)
            rep.failed += 1
        else:
            rep.accepted += 1
    rep.top_ips = Counter({ip: len(v) for ip, v in failed_by_ip.items()}).most_common(5)
    rep.top_users = Counter(e.user for v in failed_by_ip.values() for e in v).most_common(5)
    fmt = "%Y-%m-%d %H:%M:%S"

    for ip, evs in failed_by_ip.items():
        burst = detect_bursts([e.time for e in evs], threshold, timedelta(minutes=window_min))
        if burst:
            first, last, n = burst
            rep.alerts.append(Alert("HIGH", "brute_force", ip,
                                    f"{n} failed logins within {window_min} min",
                                    first.strftime(fmt), last.strftime(fmt)))
        users = {e.user for e in evs}
        if len(users) >= user_threshold:
            rep.alerts.append(Alert("MEDIUM", "user_enumeration", ip,
                                    f"{len(users)} distinct usernames tried",
                                    evs[0].time.strftime(fmt), evs[-1].time.strftime(fmt)))

    for e in events:
        prior = [f for f in failed_by_ip.get(e.ip, []) if f.time <= e.time]
        if e.kind == "accepted" and len(prior) >= threshold:
            rep.alerts.append(Alert("CRITICAL", "success_after_failures", e.ip,
                                    f"user '{e.user}' logged in after {len(prior)} failures",
                                    prior[0].time.strftime(fmt), e.time.strftime(fmt)))
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    rep.alerts.sort(key=lambda a: (order[a.severity], a.ip))
    return rep


def print_report(rep: Report) -> None:
    print("=== SSH Security Log Report ===")
    print(f"Lines: {rep.lines}  Parsed events: {rep.parsed}  Failed: {rep.failed}  Accepted: {rep.accepted}")
    print("\nTop offending IPs:  " + (", ".join(f"{i} ({n})" for i, n in rep.top_ips) or "none"))
    print("Top targeted users: " + (", ".join(f"{u} ({n})" for u, n in rep.top_users) or "none"))
    print(f"\nAlerts ({len(rep.alerts)}):")
    for a in rep.alerts:
        print(f"  [{a.severity:<8}] {a.type:<22} {a.ip:<16} {a.detail}  ({a.first_seen} -> {a.last_seen})")
    if not rep.alerts:
        print("  none")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="SSH auth log analyzer")
    ap.add_argument("logfile")
    ap.add_argument("--threshold", type=int, default=5, help="failures that trigger an alert")
    ap.add_argument("--window", type=int, default=10, help="window in minutes")
    ap.add_argument("--user-threshold", type=int, default=4, help="distinct users for enumeration alert")
    ap.add_argument("--year", type=int, default=datetime.now().year, help="syslog omits the year")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--csv", metavar="FILE", help="write alerts to CSV")
    args = ap.parse_args(argv)

    try:
        events, total = parse_log(args.logfile, args.year)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    rep = analyze(events, total, args.threshold, args.window, args.user_threshold)

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(Alert.__dataclass_fields__))
            w.writeheader()
            w.writerows(asdict(a) for a in rep.alerts)
    if args.json:
        print(json.dumps(asdict(rep), indent=2))
    else:
        print_report(rep)
    return 1 if rep.alerts else 0


if __name__ == "__main__":
    sys.exit(main())
