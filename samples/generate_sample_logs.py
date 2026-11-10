"""Generate synthetic sample logs (deterministic) with known attacks mixed into normal traffic.

All IPs come from the reserved documentation ranges (RFC 5737), so no real hosts appear.
Run:  python samples/generate_sample_logs.py
Writes samples/auth.log (year 2026) and samples/access.log next to this script.
"""
import random
from datetime import datetime, timedelta
from pathlib import Path

rng = random.Random(42)
BASE = datetime(2026, 11, 7, 0, 0, 0)
OUT = Path(__file__).resolve().parent


def at(hours, minutes=0, seconds=0):
    return BASE + timedelta(hours=hours, minutes=minutes, seconds=seconds)


# --------------------------------------------------------------------------- auth.log

def sys_ts(dt):
    return f"{dt:%b} {dt.day:>2} {dt:%H:%M:%S}"


def auth_line(dt, result, user, ip, invalid=False, method="password"):
    pid = rng.randint(1000, 30000)
    who = f"invalid user {user}" if invalid else user
    return dt, (f"{sys_ts(dt)} web01 sshd[{pid}]: {result} {method} for {who} "
                f"from {ip} port {rng.randint(20000, 60000)} ssh2")


def build_auth():
    rows = []
    # Normal: successful logins by three staff members, a few with one typo first.
    staff = {"alice": "198.51.100.7", "bob": "198.51.100.8", "carol": "198.51.100.9"}
    for _ in range(25):
        user = rng.choice(list(staff))
        t = at(rng.uniform(0, 23.9))
        if rng.random() < 0.25:
            rows.append(auth_line(t, "Failed", user, staff[user]))
            t += timedelta(seconds=rng.randint(5, 30))
        rows.append(auth_line(t, "Accepted", user, staff[user], method=rng.choice(["password", "publickey"])))

    # Attack 1: SSH brute force, 40 attempts in ~5 minutes, no success.
    t = at(3, 12)
    for _ in range(40):
        user = rng.choice(["root", "admin", "ubuntu", "test", "oracle", "postgres"])
        rows.append(auth_line(t, "Failed", user, "203.0.113.50", invalid=user != "root"))
        t += timedelta(seconds=rng.randint(5, 10))

    # Attack 2: password spraying, one attempt each against 12 usernames.
    t = at(9, 40)
    for user in ["admin", "john", "mary", "support", "info", "dev", "git", "ftp", "user", "guest", "www", "backup"]:
        rows.append(auth_line(t, "Failed", user, "203.0.113.77", invalid=True))
        t += timedelta(seconds=rng.randint(15, 25))

    # Attack 3: guessing against a real account that then succeeds (possible compromise).
    t = at(14, 5)
    for _ in range(12):
        rows.append(auth_line(t, "Failed", "deploy", "203.0.113.99"))
        t += timedelta(seconds=5)
    rows.append(auth_line(t, "Accepted", "deploy", "203.0.113.99"))

    rows.sort(key=lambda r: r[0])
    return [line for _, line in rows]


# --------------------------------------------------------------------------- access.log

PAGES = ["/", "/index.html", "/about", "/products", "/contact", "/static/app.js", "/static/style.css"]
BROWSER = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/118.0 Safari/537.36"


def web_line(dt, ip, path, status, agent=BROWSER, method="GET"):
    return dt, (f'{ip} - - [{dt:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" '
                f'{status} {rng.randint(200, 20000)} "-" "{agent}"')


def build_web():
    rows = []
    # Normal browsing from 20 visitors; a few harmless 404s (e.g. /favicon.ico).
    visitors = [f"198.51.100.{n}" for n in range(20, 40)]
    for _ in range(400):
        ip = rng.choice(visitors)
        t = at(rng.uniform(0, 23.9))
        if rng.random() < 0.03:
            rows.append(web_line(t, ip, "/favicon.ico", 404))
        else:
            rows.append(web_line(t, ip, rng.choice(PAGES), 200))

    # Attack A: directory/vulnerability scan with Nikto, 60 mostly-404 requests in 2 minutes.
    t = at(2, 30)
    probes = ["/admin", "/backup.zip", "/test.php", "/config.bak", "/old/", "/db.sql", "/login.php", "/cgi-bin/test"]
    for i in range(60):
        rows.append(web_line(t, "192.0.2.10", f"{rng.choice(probes)}?r={i}", 404, "Mozilla/5.00 (Nikto/2.1.6)"))
        t += timedelta(seconds=2)

    # Attack B: SQL injection via sqlmap.
    t = at(5, 0)
    for p in ["/products?id=1%27%20OR%20%271%27=%271",
              "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
              "/login?user=admin%27--"]:
        rows.append(web_line(t, "192.0.2.20", p, 500, "sqlmap/1.7.2#stable"))
        t += timedelta(seconds=3)

    # Attack C: reflected XSS attempts.
    t = at(7, 15)
    for p in ["/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E"]:
        rows.append(web_line(t, "192.0.2.30", p, 200))
        t += timedelta(seconds=10)

    # Attack D: path traversal (one plain, one encoded).
    t = at(11, 20)
    for p in ["/download?file=../../../../etc/passwd", "/static/..%2f..%2f..%2fetc%2fpasswd"]:
        rows.append(web_line(t, "192.0.2.40", p, 400))
        t += timedelta(seconds=4)

    # Attack E: sensitive-file probing; the server leaks /.env (HTTP 200).
    t = at(16, 45)
    for p, s in [("/.env", 200), ("/.git/config", 404), ("/wp-login.php", 404), ("/phpmyadmin/", 404)]:
        rows.append(web_line(t, "192.0.2.50", p, s))
        t += timedelta(seconds=6)

    rows.sort(key=lambda r: r[0])
    return [line for _, line in rows]


if __name__ == "__main__":
    (OUT / "auth.log").write_text("\n".join(build_auth()) + "\n")
    (OUT / "access.log").write_text("\n".join(build_web()) + "\n")
    print(f"Wrote {OUT / 'auth.log'} and {OUT / 'access.log'}")
