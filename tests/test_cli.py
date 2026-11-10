import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import generate_sample_logs as gen

from loganalyzer.cli import main

SAMPLES = Path(__file__).resolve().parents[1] / "samples"

# (rule, source IP) pairs that the generated sample logs are designed to trigger.
EXPECTED = {
    ("ssh_bruteforce", "203.0.113.50"),
    ("ssh_password_spraying", "203.0.113.77"),
    ("ssh_success_after_failures", "203.0.113.99"),
    ("web_scanning", "192.0.2.10"),
    ("web_scanner_user_agent", "192.0.2.10"),
    ("web_sql_injection", "192.0.2.20"),
    ("web_xss", "192.0.2.30"),
    ("web_path_traversal", "192.0.2.40"),
    ("web_sensitive_path_probe", "192.0.2.50"),
}


def make_logs(tmp_path):
    auth, web = tmp_path / "auth.log", tmp_path / "access.log"
    auth.write_text("\n".join(gen.build_auth()) + "\n")
    web.write_text("\n".join(gen.build_web()) + "\n")
    return str(auth), str(web)


def run_json(tmp_path, *extra):
    auth, web = make_logs(tmp_path)
    out = tmp_path / "report.json"
    code = main(["--auth", auth, "--web", web, "--year", "2026", "--format", "json",
                 "--output", str(out), *extra])
    return code, json.loads(out.read_text())


def test_all_seeded_attacks_are_detected(tmp_path):
    _, report = run_json(tmp_path)
    found = {(f["rule"], f["ip"]) for f in report["findings"]}
    assert EXPECTED <= found, f"missed: {EXPECTED - found}"


def test_no_false_positives_on_normal_traffic(tmp_path):
    # Staff and visitors (198.51.100.0/24) only generate normal traffic, typos and 404s.
    _, report = run_json(tmp_path)
    assert not [f for f in report["findings"] if f["ip"].startswith("198.51.100.")]


def test_brute_forcer_is_not_mislabelled_as_spraying(tmp_path):
    _, report = run_json(tmp_path)
    assert ("ssh_password_spraying", "203.0.113.50") not in {(f["rule"], f["ip"]) for f in report["findings"]}


def test_committed_sample_logs_match_a_fresh_generator_run():
    """Determinism check: a brand-new process must reproduce the committed samples byte for byte."""
    code = (
        "import sys, generate_sample_logs as g\n"
        "with open(sys.argv[1], 'w') as fh:\n"
        "    fh.write('\\n'.join(g.build_auth()) + '\\n\\n' + '\\n'.join(g.build_web()) + '\\n')\n"
    )
    out = Path(tempfile.mkdtemp()) / "fresh.txt"
    subprocess.run([sys.executable, "-c", code, str(out)], check=True,
                   cwd=SAMPLES, env={**os.environ, "PYTHONPATH": str(SAMPLES)})
    fresh_auth, fresh_web = out.read_text().split("\n\n", 1)
    assert fresh_auth + "\n" == (SAMPLES / "auth.log").read_text()
    assert fresh_web == (SAMPLES / "access.log").read_text()


def test_json_report_structure(tmp_path):
    _, report = run_json(tmp_path)
    assert set(report) == {"stats", "summary", "findings"}
    assert report["stats"]["auth_skipped"] == 0 and report["stats"]["web_skipped"] == 0
    assert report["summary"]["critical"] == 1


def test_fail_on_sets_exit_code(tmp_path):
    code, _ = run_json(tmp_path, "--fail-on", "high")
    assert code == 2
    code, _ = run_json(tmp_path)
    assert code == 0


def test_clean_log_exits_zero_even_with_fail_on(tmp_path):
    clean = tmp_path / "clean.log"
    clean.write_text('198.51.100.20 - - [07/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n')
    assert main(["--web", str(clean), "--fail-on", "medium"]) == 0


def test_text_report_mentions_findings(tmp_path, capsys):
    auth, web = make_logs(tmp_path)
    main(["--auth", auth, "--web", web, "--year", "2026"])
    out = capsys.readouterr().out
    assert "LOG ANALYZER REPORT" in out and "[CRITICAL]" in out and "203.0.113.99" in out


def test_requires_an_input_and_handles_missing_file(tmp_path, capsys):
    assert main([]) == 1
    assert main(["--auth", str(tmp_path / "nope.log")]) == 1
    assert "error" in capsys.readouterr().err
