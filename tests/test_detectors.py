from datetime import datetime, timedelta

from loganalyzer.detectors import (SEVERITY_ORDER, Thresholds, detect_attack_signatures,
                                   detect_password_spraying, detect_scanner_agents,
                                   detect_sensitive_paths, detect_ssh_bruteforce,
                                   detect_success_after_failures, detect_web_scanning, run_all)
from loganalyzer.parsers import AuthEvent, WebEvent

T0 = datetime(2026, 11, 7, 12, 0, 0)
TH = Thresholds()


def auth(offset_s, user="root", ip="203.0.113.5", success=False, invalid=False):
    return AuthEvent(T0 + timedelta(seconds=offset_s), "web01", success, "password", user, invalid, ip)


def web(offset_s, path="/", status=200, ip="192.0.2.1", agent="Mozilla/5.0"):
    return WebEvent(T0 + timedelta(seconds=offset_s), ip, "GET", path, status, agent)


# ------------------------------------------------------------------ SSH brute force

def test_bruteforce_not_flagged_below_threshold():
    assert detect_ssh_bruteforce([auth(i) for i in range(4)], TH) == []


def test_bruteforce_flagged_at_threshold():
    f = detect_ssh_bruteforce([auth(i * 10) for i in range(5)], TH)
    assert len(f) == 1 and f[0].ip == "203.0.113.5" and f[0].count == 5 and f[0].severity == "medium"


def test_bruteforce_slow_attempts_outside_window_not_flagged():
    # 5 failures, but 15 minutes apart: never 5 inside one 10-minute window
    assert detect_ssh_bruteforce([auth(i * 900) for i in range(5)], TH) == []


def test_bruteforce_large_burst_is_high_severity():
    f = detect_ssh_bruteforce([auth(i) for i in range(25)], TH)
    assert f[0].severity == "high"


def test_bruteforce_counts_each_ip_separately():
    evs = [auth(i, ip="203.0.113.5") for i in range(3)] + [auth(i, ip="203.0.113.6") for i in range(3)]
    assert detect_ssh_bruteforce(evs, TH) == []  # 6 total, but only 3 per source


# ------------------------------------------------------------------ password spraying

def test_spraying_many_users_few_attempts_each():
    evs = [auth(i * 20, user=f"user{i}", invalid=True) for i in range(8)]
    f = detect_password_spraying(evs, TH)
    assert len(f) == 1 and f[0].rule == "ssh_password_spraying"


def test_spraying_not_flagged_for_single_user_hammering():
    assert detect_password_spraying([auth(i) for i in range(40)], TH) == []


def test_spraying_not_flagged_when_many_attempts_per_user():
    # 6 users x 7 attempts each = brute force, not spraying
    evs = [auth(i, user=f"u{i % 6}") for i in range(42)]
    assert detect_password_spraying(evs, TH) == []


# ------------------------------------------------------------------ success after failures

def test_success_after_failure_burst_is_critical():
    evs = [auth(i * 5) for i in range(6)] + [auth(40, user="deploy", success=True)]
    f = detect_success_after_failures(evs, TH)
    assert len(f) == 1 and f[0].severity == "critical" and "deploy" in f[0].detail


def test_single_typo_then_success_not_flagged():
    evs = [auth(0, user="alice"), auth(10, user="alice", success=True)]
    assert detect_success_after_failures(evs, TH) == []


def test_success_long_after_failures_not_flagged():
    evs = [auth(i) for i in range(6)] + [auth(3600, success=True)]  # an hour later
    assert detect_success_after_failures(evs, TH) == []


def test_success_from_different_ip_not_correlated():
    evs = [auth(i) for i in range(6)] + [auth(30, ip="198.51.100.7", success=True)]
    assert detect_success_after_failures(evs, TH) == []


# ------------------------------------------------------------------ web rules

def test_web_scanning_threshold():
    assert detect_web_scanning([web(i, "/x", 404) for i in range(14)], TH) == []
    f = detect_web_scanning([web(i, "/x", 404) for i in range(15)], TH)
    assert len(f) == 1 and f[0].count == 15


def test_web_scanning_ignores_successful_requests():
    assert detect_web_scanning([web(i, "/", 200) for i in range(100)], TH) == []


def test_sensitive_path_200_is_high_severity():
    f = detect_sensitive_paths([web(0, "/.env", 200)], TH)
    assert f[0].severity == "high" and "200" in f[0].detail


def test_sensitive_path_404_is_medium():
    assert detect_sensitive_paths([web(0, "/wp-login.php", 404)], TH)[0].severity == "medium"


def test_normal_pages_not_flagged_as_sensitive():
    evs = [web(0, "/"), web(1, "/products?id=3"), web(2, "/static/app.js"), web(3, "/about")]
    assert detect_sensitive_paths(evs, TH) == []


def test_signature_detection_each_attack_type():
    cases = {
        "web_sql_injection": "/p?id=1%20UNION%20SELECT%20password%20FROM%20users",
        "web_xss": "/s?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "web_path_traversal": "/d?f=../../etc/passwd",
        "web_command_injection": "/ping?host=8.8.8.8;cat%20/etc/passwd",
    }
    for rule, path in cases.items():
        rules = {f.rule for f in detect_attack_signatures([web(0, path)], TH)}
        assert rule in rules, f"{rule} not detected for {path}"


def test_signature_detection_handles_double_encoding():
    f = detect_attack_signatures([web(0, "/d?f=%252e%252e%252f%252e%252e%252fetc/passwd")], TH)
    assert any(x.rule == "web_path_traversal" for x in f)


def test_benign_urls_do_not_trigger_signatures():
    benign = ["/", "/products?id=42&sort=price", "/search?q=red+shoes", "/blog/2026/union-station-guide",
              "/api/v1/users?page=2"]
    assert detect_attack_signatures([web(i, p) for i, p in enumerate(benign)], TH) == []


def test_scanner_user_agent():
    f = detect_scanner_agents([web(0, agent="sqlmap/1.7.2#stable"), web(1, ip="192.0.2.9")], TH)
    assert len(f) == 1 and f[0].ip == "192.0.2.1"


# ------------------------------------------------------------------ orchestration

def test_run_all_sorts_most_severe_first():
    auth_evs = [auth(i * 5) for i in range(6)] + [auth(40, success=True)]  # critical + medium
    web_evs = [web(0, "/s?q=<script>", 200)]                                # high
    sev = [SEVERITY_ORDER[f.severity] for f in run_all(auth_evs, web_evs)]
    assert sev == sorted(sev) and sev[0] == SEVERITY_ORDER["critical"]


def test_run_all_empty_input():
    assert run_all([], []) == []
