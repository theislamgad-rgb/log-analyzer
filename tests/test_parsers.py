from datetime import datetime

from loganalyzer.parsers import (parse_auth_file, parse_auth_line, parse_web_file,
                                 parse_web_line)

FAILED = "Nov  8 12:01:02 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 4242 ssh2"
INVALID = "Nov  8 12:01:07 web01 sshd[1235]: Failed password for invalid user admin from 203.0.113.5 port 4243 ssh2"
ACCEPTED = "Nov 18 09:15:00 web01 sshd[99]: Accepted publickey for alice from 198.51.100.7 port 5000 ssh2"
NOISE = "Nov  8 12:01:09 web01 sshd[1236]: Connection closed by 203.0.113.5 port 4243 [preauth]"
WEB = ('203.0.113.9 - - [08/Nov/2026:12:00:01 +0200] "GET /index.html?a=1 HTTP/1.1" 200 512 '
       '"-" "Mozilla/5.0"')


def test_failed_login_valid_user():
    e = parse_auth_line(FAILED, 2026)
    assert (e.success, e.user, e.ip, e.invalid_user) == (False, "root", "203.0.113.5", False)
    assert e.ts == datetime(2026, 11, 8, 12, 1, 2)


def test_failed_login_invalid_user():
    e = parse_auth_line(INVALID, 2026)
    assert e.user == "admin" and e.invalid_user and not e.success


def test_accepted_login_two_digit_day():
    e = parse_auth_line(ACCEPTED, 2026)
    assert e.success and e.method == "publickey" and e.ts.day == 18


def test_non_login_sshd_line_is_ignored():
    assert parse_auth_line(NOISE, 2026) is None


def test_web_line_fields_and_utc_conversion():
    e = parse_web_line(WEB)
    assert (e.ip, e.method, e.path, e.status, e.agent) == (
        "203.0.113.9", "GET", "/index.html?a=1", 200, "Mozilla/5.0")
    assert e.ts == datetime(2026, 11, 8, 10, 0, 1)  # +02:00 converted to UTC


def test_garbage_lines_return_none():
    assert parse_web_line("not a log line") is None
    assert parse_auth_line("", 2026) is None


def test_file_parsing_counts_skipped_lines(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text("\n".join([FAILED, NOISE, "garbage", "", ACCEPTED]) + "\n")
    events, skipped = parse_auth_file(str(p), 2026)
    assert len(events) == 2 and skipped == 2  # blank lines are not counted as skipped

    w = tmp_path / "access.log"
    w.write_text(WEB + "\nbroken line\n")
    events, skipped = parse_web_file(str(w))
    assert len(events) == 1 and skipped == 1
