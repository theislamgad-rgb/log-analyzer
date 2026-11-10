"""Parsers for two common log formats.

* OpenSSH auth log lines (syslog style, as found in /var/log/auth.log)
* Web access logs in the Apache/Nginx "combined" format

Lines that don't match are counted and skipped, never fatal.
"""
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, List, Tuple

AUTH_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) sshd\[\d+\]: "
    r"(?P<result>Failed|Accepted) (?P<method>\S+) for (?P<invalid>invalid user )?"
    r"(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)

WEB_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) (?P<size>\S+) '
    r'"[^"]*" "(?P<agent>[^"]*)"'
)


@dataclass(frozen=True)
class AuthEvent:
    ts: datetime          # naive; syslog has no year/timezone, so the caller supplies the year
    host: str
    success: bool
    method: str
    user: str
    invalid_user: bool    # username does not exist on the host
    ip: str


@dataclass(frozen=True)
class WebEvent:
    ts: datetime          # naive, converted to UTC
    ip: str
    method: str
    path: str             # path + query string, as logged
    status: int
    agent: str


def parse_auth_line(line: str, year: int):
    m = AUTH_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    return AuthEvent(
        ts=ts, host=m["host"], success=m["result"] == "Accepted", method=m["method"],
        user=m["user"], invalid_user=bool(m["invalid"]), ip=m["ip"],
    )


def parse_web_line(line: str):
    m = WEB_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    return WebEvent(ts=ts, ip=m["ip"], method=m["method"], path=m["path"],
                    status=int(m["status"]), agent=m["agent"])


def _parse_lines(lines: Iterable[str], parse) -> Tuple[list, int]:
    events, skipped = [], 0
    for raw in lines:
        raw = raw.rstrip("\n")
        if not raw.strip():
            continue
        ev = parse(raw)
        if ev is None:
            skipped += 1
        else:
            events.append(ev)
    return events, skipped


def parse_auth_file(path: str, year: int) -> Tuple[List[AuthEvent], int]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        events, skipped = _parse_lines(fh, lambda l: parse_auth_line(l, year))
    # sshd lines that aren't login results (e.g. "Connection closed") are expected noise.
    return sorted(events, key=lambda e: e.ts), skipped


def parse_web_file(path: str) -> Tuple[List[WebEvent], int]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        events, skipped = _parse_lines(fh, parse_web_line)
    return sorted(events, key=lambda e: e.ts), skipped
