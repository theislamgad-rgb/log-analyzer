"""Command-line interface."""
import argparse
import sys
from datetime import datetime

from . import __version__
from .detectors import SEVERITY_ORDER, Thresholds, run_all
from .parsers import parse_auth_file, parse_web_file
from .report import render_json, render_text


def build_parser():
    p = argparse.ArgumentParser(
        prog="loganalyzer",
        description="Analyze SSH auth logs and web access logs for suspicious activity.")
    p.add_argument("--auth", help="path to an OpenSSH auth log (syslog format)")
    p.add_argument("--web", help="path to a web access log (Apache/Nginx combined format)")
    p.add_argument("--year", type=int, default=datetime.now().year,
                   help="year for auth-log timestamps, which don't include one (default: current year)")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--output", help="write the report to this file instead of stdout")
    p.add_argument("--fail-on", choices=("critical", "high", "medium"),
                   help="exit with status 2 if any finding is at least this severe (useful in CI/cron)")
    d = Thresholds()
    p.add_argument("--ssh-fail-count", type=int, default=d.ssh_fail_count)
    p.add_argument("--ssh-window-min", type=int, default=d.ssh_window_min)
    p.add_argument("--spray-users", type=int, default=d.spray_distinct_users)
    p.add_argument("--spray-max-attempts", type=float, default=d.spray_max_attempts,
                   help="max average attempts per username to still count as spraying")
    p.add_argument("--web-error-count", type=int, default=d.web_error_count)
    p.add_argument("--web-window-min", type=int, default=d.web_window_min)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not (args.auth or args.web):
        print("error: give at least one of --auth or --web", file=sys.stderr)
        return 1

    try:
        auth, auth_skipped = parse_auth_file(args.auth, args.year) if args.auth else ([], 0)
        web, web_skipped = parse_web_file(args.web) if args.web else ([], 0)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    th = Thresholds(
        ssh_fail_count=args.ssh_fail_count, ssh_window_min=args.ssh_window_min,
        spray_distinct_users=args.spray_users, spray_max_attempts=args.spray_max_attempts,
        web_error_count=args.web_error_count,
        web_window_min=args.web_window_min)
    findings = run_all(auth, web, th)
    stats = {"auth_events": len(auth), "auth_skipped": auth_skipped,
             "web_events": len(web), "web_skipped": web_skipped}

    report = (render_json if args.format == "json" else render_text)(findings, stats)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
    else:
        print(report)

    if args.fail_on and any(SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[args.fail_on] for f in findings):
        return 2
    return 0
