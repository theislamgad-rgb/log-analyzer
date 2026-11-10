"""Detection rules. Each rule takes parsed events and returns a list of Finding objects.

Rules are deliberately simple and explainable (thresholds + sliding windows +
signatures), so every alert can be justified from the raw log lines.
"""
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from typing import Dict, List
from urllib.parse import unquote_plus

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Thresholds:
    ssh_fail_count: int = 5          # failures from one IP ...
    ssh_window_min: int = 10         # ... inside this many minutes
    spray_distinct_users: int = 5    # one IP failing against this many distinct usernames ...
    spray_max_attempts: float = 3.0  # ... with at most this many attempts per username on average
    web_error_count: int = 15        # 403/404 responses to one IP ...
    web_window_min: int = 5          # ... inside this many minutes


@dataclass
class Finding:
    rule: str
    severity: str
    ip: str
    count: int
    first_seen: str
    last_seen: str
    detail: str
    source: str  # "auth" or "web"

    def to_dict(self) -> Dict:
        return asdict(self)


def _iso(dt):
    return dt.isoformat(sep=" ")


def _max_window(times, window: timedelta):
    """Largest number of events inside any sliding window. Returns (count, first_idx, last_idx)."""
    best, j = (0, 0, 0), 0
    for i, t in enumerate(times):
        while t - times[j] > window:
            j += 1
        if i - j + 1 > best[0]:
            best = (i - j + 1, j, i)
    return best


def _group_by_ip(events):
    groups = defaultdict(list)
    for e in events:
        groups[e.ip].append(e)
    return groups


# --------------------------------------------------------------------------- SSH rules

def detect_ssh_bruteforce(events, th: Thresholds) -> List[Finding]:
    findings = []
    window = timedelta(minutes=th.ssh_window_min)
    for ip, evs in _group_by_ip(e for e in events if not e.success).items():
        n, a, b = _max_window([e.ts for e in evs], window)
        if n >= th.ssh_fail_count:
            users = sorted({e.user for e in evs})
            findings.append(Finding(
                rule="ssh_bruteforce",
                severity="high" if n >= 4 * th.ssh_fail_count else "medium",
                ip=ip, count=n, first_seen=_iso(evs[a].ts), last_seen=_iso(evs[b].ts),
                detail=f"{n} failed SSH logins within {th.ssh_window_min} min "
                       f"(targets: {', '.join(users[:5])}{'...' if len(users) > 5 else ''})",
                source="auth"))
    return findings


def detect_password_spraying(events, th: Thresholds) -> List[Finding]:
    """Spraying = many different usernames, only a few attempts each (the attacker
    stays under per-account lockouts). Many attempts per username is plain brute force,
    which detect_ssh_bruteforce already covers."""
    findings = []
    for ip, evs in _group_by_ip(e for e in events if not e.success).items():
        users = {e.user for e in evs}
        per_user = len(evs) / len(users)
        if len(users) >= th.spray_distinct_users and per_user <= th.spray_max_attempts:
            findings.append(Finding(
                rule="ssh_password_spraying", severity="high", ip=ip, count=len(evs),
                first_seen=_iso(evs[0].ts), last_seen=_iso(evs[-1].ts),
                detail=f"{len(users)} different usernames, ~{per_user:.1f} attempt(s) each "
                       f"({sum(e.invalid_user for e in evs)} attempts used non-existent users)",
                source="auth"))
    return findings


def detect_success_after_failures(events, th: Thresholds) -> List[Finding]:
    """A successful login right after a burst of failures from the same IP is the
    highest-value alert: the guessing may have worked."""
    findings = []
    window = timedelta(minutes=th.ssh_window_min)
    by_ip = _group_by_ip(events)
    for ip, evs in by_ip.items():
        for ev in (e for e in evs if e.success):
            recent = [e for e in evs if not e.success and timedelta(0) <= ev.ts - e.ts <= window]
            if len(recent) >= th.ssh_fail_count:
                findings.append(Finding(
                    rule="ssh_success_after_failures", severity="critical", ip=ip,
                    count=len(recent), first_seen=_iso(recent[0].ts), last_seen=_iso(ev.ts),
                    detail=f"{len(recent)} failures then a successful login as '{ev.user}' "
                           f"({ev.method}); treat the account as possibly compromised",
                    source="auth"))
                break  # one alert per IP is enough
    return findings


# --------------------------------------------------------------------------- web rules

SENSITIVE_PATH_RE = re.compile(
    r"^/(\.env|\.git(/|$)|wp-login\.php|wp-admin|phpmyadmin|admin|server-status|backup|etc/passwd)",
    re.I)

SIGNATURES = {
    "sql_injection": re.compile(
        r"(union\s+select|'\s*or\s*'?\d|\bor\s+1\s*=\s*1|'--|sleep\s*\(|information_schema|;\s*drop\s+table)", re.I),
    "xss": re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|<img[^>]+src)", re.I),
    "path_traversal": re.compile(r"(\.\./|\.\.\\)"),
    "command_injection": re.compile(r"(;\s*(cat|ls|id|whoami|wget|curl)\b|\|\s*(cat|id|whoami)\b|\$\(|`)", re.I),
}

SCANNER_AGENTS = re.compile(r"(sqlmap|nikto|nmap|masscan|nessus|acunetix|dirbuster|gobuster)", re.I)


def _decode(path: str) -> str:
    # Decode twice to catch double-encoded payloads (%252e%252e%252f).
    return unquote_plus(unquote_plus(path))


def detect_web_scanning(events, th: Thresholds) -> List[Finding]:
    findings = []
    window = timedelta(minutes=th.web_window_min)
    errors = (e for e in events if e.status in (403, 404))
    for ip, evs in _group_by_ip(errors).items():
        n, a, b = _max_window([e.ts for e in evs], window)
        if n >= th.web_error_count:
            findings.append(Finding(
                rule="web_scanning", severity="medium", ip=ip, count=n,
                first_seen=_iso(evs[a].ts), last_seen=_iso(evs[b].ts),
                detail=f"{n} 403/404 responses within {th.web_window_min} min "
                       f"(forced browsing or directory/vulnerability scan)",
                source="web"))
    return findings


def detect_sensitive_paths(events, th: Thresholds) -> List[Finding]:
    findings = []
    for ip, evs in _group_by_ip(events).items():
        hits = [e for e in evs if SENSITIVE_PATH_RE.match(_decode(e.path.split("?")[0]))]
        if not hits:
            continue
        served = [e for e in hits if e.status == 200]
        paths = sorted({e.path.split("?")[0] for e in hits})
        findings.append(Finding(
            rule="web_sensitive_path_probe",
            severity="high" if served else "medium", ip=ip, count=len(hits),
            first_seen=_iso(hits[0].ts), last_seen=_iso(hits[-1].ts),
            detail=f"requested sensitive paths: {', '.join(paths[:5])}"
                   f"{'; SERVER RETURNED 200 for ' + served[0].path.split('?')[0] if served else ''}",
            source="web"))
    return findings


def detect_attack_signatures(events, th: Thresholds) -> List[Finding]:
    findings = []
    for ip, evs in _group_by_ip(events).items():
        per_type = defaultdict(list)
        for e in evs:
            decoded = _decode(e.path)
            for name, rx in SIGNATURES.items():
                if rx.search(decoded):
                    per_type[name].append(e)
        for name, hits in per_type.items():
            findings.append(Finding(
                rule=f"web_{name}", severity="high", ip=ip, count=len(hits),
                first_seen=_iso(hits[0].ts), last_seen=_iso(hits[-1].ts),
                detail=f"{len(hits)} request(s) matching {name.replace('_', ' ')} patterns, "
                       f"e.g. {_decode(hits[0].path)[:80]!r}",
                source="web"))
    return findings


def detect_scanner_agents(events, th: Thresholds) -> List[Finding]:
    findings = []
    for ip, evs in _group_by_ip(events).items():
        hits = [e for e in evs if SCANNER_AGENTS.search(e.agent)]
        if hits:
            findings.append(Finding(
                rule="web_scanner_user_agent", severity="high", ip=ip, count=len(hits),
                first_seen=_iso(hits[0].ts), last_seen=_iso(hits[-1].ts),
                detail=f"known security-scanner User-Agent: {hits[0].agent[:60]!r}",
                source="web"))
    return findings


AUTH_RULES = [detect_ssh_bruteforce, detect_password_spraying, detect_success_after_failures]
WEB_RULES = [detect_web_scanning, detect_sensitive_paths, detect_attack_signatures, detect_scanner_agents]


def run_all(auth_events, web_events, th: Thresholds = None) -> List[Finding]:
    th = th or Thresholds()
    findings: List[Finding] = []
    for rule in AUTH_RULES:
        findings += rule(auth_events, th)
    for rule in WEB_RULES:
        findings += rule(web_events, th)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], -f.count, f.ip, f.rule))
    return findings
