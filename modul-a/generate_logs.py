#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
generate_logs.py - SOC Modul C / Modul A: Log Generatoru

Yaradır (JSON Lines, hər sətir = 1 müstəqil JSON event, timestamp = ISO 8601 UTC):
    linux_auth.jsonl   web_access.jsonl   firewall.jsonl
    + expected_results.md + baseline.md

Əsas rejimlər:
    python generate_logs.py                       # small + large dataset, expected_results.md, baseline.md
    python generate_logs.py --profile small       # yalnız kiçik test dataset (Modul B-yə ilk təhvil)
    python generate_logs.py --append-to DIR       # mövcud böyük dataset-ə YALNIZ ssenari event-lərini əlavə edir
    python generate_logs.py --verify DIR          # format + detection yoxlaması
    python generate_logs.py --measure DIR         # DIR üçün baseline cədvəli (event sayı, ölçü, EPS, GB/day)

Yalnız standart Python 3.8+ kitabxanası istifadə olunur. Dataset tam sintetikdir
(RFC 5737 sənəd IP aralıqları: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
"""
import argparse
import json
import os
import random
import re
import sys
import time
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone

# --------------------------------------------------------------------------
# Sabitlər
# --------------------------------------------------------------------------
TS_FMT = "%Y-%m-%dT%H:%M:%SZ"
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
DEBUG = "synthetic-test"
PASSWORD_SAMPLE = "Secret123!"        # sintetik - maskalama testi üçün açıq qalmalıdır
SECRET_QUERY = "token=xyz123secret"   # sintetik - maskalama testi üçün açıq qalmalıdır
SOURCES = ("linux_auth", "web_access", "firewall")
FILES = {s: s + ".jsonl" for s in SOURCES}
DEFAULT_SCENARIO_TIME = "2026-11-07T10:00:00Z"

REQUIRED = {
    "linux_auth": ["timestamp", "source_type", "event_type", "source_ip", "username",
                   "outcome", "process", "password_sample", "message", "debug_info"],
    "web_access": ["timestamp", "source_type", "event_type", "source_ip", "http_method",
                   "url_path", "url_query", "status_code", "user_agent", "response_bytes",
                   "debug_info"],
    "firewall": ["timestamp", "source_type", "event_type", "source_ip", "destination_ip",
                 "destination_port", "action", "protocol", "rule", "raw_message"],
}

# Aşkarlama qaydaları (expected_results.md və --verify eyni qaydaları istifadə edir)
RULES = {
    "ssh_bruteforce": "Eyni source_ip + eyni username, process=sshd, outcome=failure: 60 san ərzində >= 5",
    "suspicious_admin_login": "username in (root, demo_admin), process=sshd, outcome=success",
    "password_spraying": "Eyni source_ip, process=sshd, outcome=failure: 60 san ərzində >= 5 FƏRQLİ username",
    "web_repeated_failed_login": "Eyni source_ip, POST /login, status_code=401: 60 san ərzində >= 5",
    "port_scan": "Eyni source_ip, action=BLOCK: 30 san ərzində >= 3 FƏRQLİ destination_port",
}

# Fon (noise) trafiki üçün IP hovuzu - ssenari IP-lərindən (192.0.2.x) ayrıdır
NOISE_POOL = ([f"198.51.100.{i}" for i in range(1, 255)] +
              [f"203.0.113.{i}" for i in range(1, 255)])
MIN_GAP = 20  # eyni fon IP-si eyni mənbədə ən azı 20 san fasilə ilə görünür -> təsadüfi false-positive olmur

NORMAL_USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "deploy", "jenkins"]
USER_AGENTS = [
    "Mozilla/5.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0",
    "curl/8.4.0",
    "python-requests/2.31.0",
]


# --------------------------------------------------------------------------
# Vaxt köməkçiləri
# --------------------------------------------------------------------------
def iso(dt):
    return dt.astimezone(timezone.utc).strftime(TS_FMT)


def iso_epoch(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime(TS_FMT)


def parse_ts(s):
    return datetime.strptime(s, TS_FMT).replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# Event konstruktorları (sahə sırası tapşırıqdakı nümunələrə uyğundur)
# --------------------------------------------------------------------------
def linux_event(ts, event_type, ip, user, outcome, process, message):
    return {"timestamp": ts, "source_type": "linux_auth", "event_type": event_type,
            "source_ip": ip, "username": user, "outcome": outcome, "process": process,
            "password_sample": PASSWORD_SAMPLE, "message": message, "debug_info": DEBUG}


def ssh_event(ts, ip, user, outcome):
    msg = "Failed SSH login attempt" if outcome == "failure" else "Accepted SSH login"
    return linux_event(ts, "ssh_login", ip, user, outcome, "sshd", msg)


def web_event(ts, ip, method, path, query, status, ua, size):
    return {"timestamp": ts, "source_type": "web_access", "event_type": "http_request",
            "source_ip": ip, "http_method": method, "url_path": path, "url_query": query,
            "status_code": status, "user_agent": ua, "response_bytes": size,
            "debug_info": DEBUG}


def fw_event(ts, src, dst, port, action, proto, rule, raw):
    return {"timestamp": ts, "source_type": "firewall", "event_type": "firewall_connection",
            "source_ip": src, "destination_ip": dst, "destination_port": port,
            "action": action, "protocol": proto, "rule": rule, "raw_message": raw}


# --------------------------------------------------------------------------
# Test ssenariləri (positive / negative) - hər ssenari üçün ayrıca source_ip
# --------------------------------------------------------------------------
def build_scenarios(base):
    """base: ilk ssenarinin başlama vaxtı (datetime, UTC). Qaytarır: (events_by_source, meta)."""
    events = {s: [] for s in SOURCES}
    meta = []

    def T(o):
        return iso(base + timedelta(seconds=o))

    def add(sid, name, kind, source, ip, evs, detects, not_detects, detail, expect):
        events[source].extend(evs)
        ts = [e["timestamp"] for e in evs]
        meta.append({"id": sid, "name": name, "kind": kind, "source": source, "ip": ip,
                     "start": min(ts), "end": max(ts), "count": len(evs),
                     "detects": detects, "not_detects": not_detects,
                     "detail": detail, "expect": expect})

    # ---- Linux authentication ----
    ip = "192.0.2.10"; t0 = 0
    add("A1", "SSH Brute-Force", "positive", "linux_auth", ip,
        [ssh_event(T(t0 + i * 8), ip, "admin", "failure") for i in range(6)],
        ["ssh_bruteforce"], ["password_spraying"],
        "username=admin üçün 6 failure, 8 san aralıqla (40 san)",
        "SSH Brute-Force aşkarlanmalıdır")

    ip = "192.0.2.11"; t0 = 120
    add("A2", "Suspicious Admin Login", "positive", "linux_auth", ip,
        [ssh_event(T(t0), ip, "root", "success"),
         ssh_event(T(t0 + 10), ip, "demo_admin", "success")],
        ["suspicious_admin_login"], ["ssh_bruteforce", "password_spraying"],
        "root və demo_admin ilə success login (sshd)",
        "Suspicious Admin Login aşkarlanmalıdır (2 event)")

    ip = "192.0.2.12"; t0 = 240
    users = ["admin", "test", "guest", "oracle", "postgres"]
    add("A3", "Password Spraying - positive", "positive", "linux_auth", ip,
        [ssh_event(T(t0 + i * 10), ip, u, "failure") for i, u in enumerate(users)],
        ["password_spraying"], ["ssh_bruteforce"],
        "5 fərqli username, hər biri üçün 1 failure, 10 san aralıqla (40 san)",
        "Password Spraying aşkarlanmalıdır; Brute-Force aşkarlanmamalıdır")

    ip = "192.0.2.13"; t0 = 360
    add("A4", "Password Spraying - negative 1", "negative", "linux_auth", ip,
        [ssh_event(T(t0 + i * 15), ip, u, "failure") for i, u in enumerate(["admin", "test", "guest"])],
        [], ["password_spraying", "ssh_bruteforce"],
        "yalnız 3 fərqli username, hər biri üçün 1 failure (30 san)",
        "Heç bir detection işləməməlidir (Spraying eşiyi 5-dir)")

    ip = "192.0.2.14"; t0 = 480
    add("A5", "Password Spraying - negative 2 (Brute-Force)", "negative", "linux_auth", ip,
        [ssh_event(T(t0 + i * 10), ip, "svc_backup", "failure") for i in range(5)],
        ["ssh_bruteforce"], ["password_spraying"],
        "eyni username (svc_backup) üçün 5 failure (40 san)",
        "Brute-Force aşkarlanmalıdır, Password Spraying aşkarlanmamalıdır")

    # ---- Web access ----
    ua = "Mozilla/5.0"
    ip = "192.0.2.20"; t0 = 600
    add("W1", "Repeated Failed Login", "positive", "web_access", ip,
        [web_event(T(t0 + i * 8), ip, "POST", "/login", SECRET_QUERY, 401, ua, 512) for i in range(6)],
        ["web_repeated_failed_login"], [],
        "6 x POST /login, status_code=401, 8 san aralıqla (40 san)",
        "Repeated Failed Login aşkarlanmalıdır")

    ip = "192.0.2.21"; t0 = 720
    add("W2", "Repeated Failed Login - negative (az saylı)", "negative", "web_access", ip,
        [web_event(T(t0 + i * 20), ip, "POST", "/login", SECRET_QUERY, 401, ua, 512) for i in range(3)],
        [], ["web_repeated_failed_login"],
        "yalnız 3 x POST /login 401 (40 san) - əlavə negative",
        "Aşkarlanmamalıdır (eşik 5)")

    ip = "192.0.2.22"; t0 = 840
    add("W3", "Repeated Failed Login - negative (status 200)", "negative", "web_access", ip,
        [web_event(T(t0 + i * 10), ip, "POST", "/login", SECRET_QUERY, 200, ua, 1024) for i in range(5)],
        [], ["web_repeated_failed_login"],
        "5 x POST /login, lakin status_code=200 - əlavə negative",
        "Aşkarlanmamalıdır (status_code != 401)")

    # ---- Firewall ----
    dst = "192.0.2.100"
    ip = "192.0.2.30"; t0 = 960
    ports = [21, 22, 23, 80, 443, 3389]
    add("F1", "Port Scanning", "positive", "firewall", ip,
        [fw_event(T(t0 + i * 4), ip, dst, p, "BLOCK", "TCP",
                  "deny_ssh" if p == 22 else "deny_default",
                  f"Synthetic blocked connection to port {p}") for i, p in enumerate(ports)],
        ["port_scan"], [],
        "6 fərqli destination_port, action=BLOCK, 4 san aralıqla (20 san)",
        "Port Scanning aşkarlanmalıdır")

    ip = "192.0.2.31"; t0 = 1080
    add("F2", "Port Scanning - negative (yavaş)", "negative", "firewall", ip,
        [fw_event(T(t0 + i * 40), ip, dst, p, "BLOCK", "TCP", "deny_default",
                  f"Synthetic blocked connection to port {p}") for i, p in enumerate([23, 445, 3306])],
        [], ["port_scan"],
        "3 fərqli port BLOCK, lakin 40 san aralıqla (heç bir 30 san pəncərəsində 3 port yoxdur) - əlavə negative",
        "Aşkarlanmamalıdır")

    ip = "192.0.2.32"; t0 = 1200
    add("F3", "Port Scanning - negative (ALLOW)", "negative", "firewall", ip,
        [fw_event(T(t0 + i * 5), ip, dst, p, "ALLOW", "TCP", "allow_general",
                  f"Synthetic allowed connection to port {p}") for i, p in enumerate([80, 443, 22, 53, 8080])],
        [], ["port_scan"],
        "5 fərqli port, lakin action=ALLOW - əlavə negative",
        "Aşkarlanmamalıdır (action != BLOCK)")

    return events, meta


# --------------------------------------------------------------------------
# Fon (noise) trafiki
# --------------------------------------------------------------------------
class IpPicker:
    """Fon IP-lərini seçir və eyni IP-nin ardıcıl event-ləri arasında MIN_GAP saxlayır."""

    def __init__(self, rng):
        self.rng = rng
        self.last = {}

    def pick(self, t):
        for _ in range(100):
            ip = self.rng.choice(NOISE_POOL)
            if t - self.last.get(ip, -10 ** 9) >= MIN_GAP:
                self.last[ip] = t
                return ip
        for ip in NOISE_POOL:
            if t - self.last.get(ip, -10 ** 9) >= MIN_GAP:
                self.last[ip] = t
                return ip
        raise RuntimeError("Fon IP hovuzu tükəndi: event sıxlığı çox yüksəkdir, vaxt pəncərəsini artırın.")


def noise_linux(t, picker, rng):
    ts = iso_epoch(t)
    if rng.random() < 0.08:  # sudo hadisələri (sshd deyil -> detection qaydalarına düşmür)
        return linux_event(ts, "sudo_auth", "127.0.0.1", rng.choice(NORMAL_USERS),
                           "success", "sudo", "sudo authentication succeeded")
    outcome = "success" if rng.random() < 0.75 else "failure"
    return ssh_event(ts, picker.pick(t), rng.choice(NORMAL_USERS), outcome)


WEB_PATHS = ["/", "/index.html", "/products", "/about", "/api/v1/items", "/static/app.js",
             "/login", "/admin", "/api/v1/orders"]
WEB_QUERIES = [None, None, None, None, SECRET_QUERY, SECRET_QUERY,
               SECRET_QUERY + "&session=test123", "page=2&sort=asc", "q=test", "lang=az"]


def noise_web(t, picker, rng):
    r = rng.random()
    status = (200 if r < 0.70 else 304 if r < 0.78 else 301 if r < 0.82 else 404 if r < 0.90
              else 500 if r < 0.92 else 401 if r < 0.96 else 403)
    path = rng.choice(WEB_PATHS)
    method = "POST" if (path in ("/login", "/api/v1/orders") and rng.random() < 0.5) else "GET"
    return web_event(iso_epoch(t), picker.pick(t), method, path, rng.choice(WEB_QUERIES),
                     status, rng.choice(USER_AGENTS), rng.randint(120, 52000))


def noise_firewall(t, picker, rng):
    ts = iso_epoch(t)
    src = picker.pick(t)
    r = rng.random()
    if r < 0.85:
        port = rng.choice([80, 443, 53, 123, 25, 8080])
        proto = "UDP" if port in (53, 123) else "TCP"
        dst = f"10.10.0.{rng.randint(2, 50)}"
        return fw_event(ts, src, dst, port, "ALLOW", proto, "allow_general",
                        "Synthetic allowed connection")
    port = rng.choice([23, 445, 1433, 3306, 5900, 8081])
    dst = f"10.10.0.{rng.randint(2, 50)}"
    if r < 0.95:
        return fw_event(ts, src, dst, port, "BLOCK", "TCP", "deny_default",
                        "Synthetic blocked connection")
    return fw_event(ts, src, dst, port, "DROP", "TCP", "drop_invalid",
                    "Synthetic dropped connection")


NOISE_FUNCS = {"linux_auth": noise_linux, "web_access": noise_web, "firewall": noise_firewall}


def gen_noise(source, n, start_dt, duration_s, seed):
    rng = random.Random(f"{seed}-{source}")
    picker = IpPicker(rng)
    start = int(start_dt.timestamp())
    times = sorted(start + rng.randrange(duration_s) for _ in range(n))
    fn = NOISE_FUNCS[source]
    return [fn(t, picker, rng) for t in times]


# --------------------------------------------------------------------------
# Fayla yazma
# --------------------------------------------------------------------------
def dumps(e):
    return json.dumps(e, ensure_ascii=False, separators=(",", ":"))


def write_jsonl(path, events, append=False):
    prefix = ""
    if append and os.path.exists(path) and os.path.getsize(path) > 0:
        with open(path, "rb") as f:
            f.seek(-1, os.SEEK_END)
            if f.read(1) != b"\n":
                prefix = "\n"
    with open(path, "a" if append else "w", encoding="utf-8", newline="\n") as f:
        if prefix:
            f.write(prefix)
        for e in events:
            f.write(dumps(e) + "\n")


def generate_profile(name, outdir, base, noise_counts, noise_start, noise_duration, seed):
    d = os.path.join(outdir, name)
    os.makedirs(d, exist_ok=True)
    scen, meta = build_scenarios(base)
    timings = {}
    for s in SOURCES:
        t0 = time.perf_counter()
        events = scen[s] + gen_noise(s, noise_counts[s], noise_start, noise_duration, seed)
        events.sort(key=lambda e: e["timestamp"])  # stabil sort
        write_jsonl(os.path.join(d, FILES[s]), events)
        timings[s] = time.perf_counter() - t0
    return d, meta, timings


# --------------------------------------------------------------------------
# Yoxlama (format + detection)
# --------------------------------------------------------------------------
def load_events(path):
    events, errors = [], []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                errors.append(f"{os.path.basename(path)}:{n}: boş sətir")
                continue
            try:
                e = json.loads(line)
            except ValueError as ex:
                errors.append(f"{os.path.basename(path)}:{n}: JSON parse xətası ({ex})")
                continue
            if not isinstance(e, dict):
                errors.append(f"{os.path.basename(path)}:{n}: obyekt deyil")
                continue
            events.append(e)
    return events, errors


def validate(source, events):
    errors = []
    for i, e in enumerate(events, 1):
        miss = [k for k in REQUIRED[source] if k not in e]
        if miss:
            errors.append(f"{source} #{i}: çatışmayan field-lər {miss}")
        if e.get("source_type") != source:
            errors.append(f"{source} #{i}: source_type səhvdir ({e.get('source_type')})")
        if not TS_RE.match(str(e.get("timestamp", ""))):
            errors.append(f"{source} #{i}: timestamp formatı səhvdir")
        if source == "linux_auth" and e.get("outcome") not in ("success", "failure"):
            errors.append(f"{source} #{i}: outcome səhvdir")
        if source == "firewall" and e.get("action") not in ("ALLOW", "BLOCK", "DROP"):
            errors.append(f"{source} #{i}: action səhvdir")
    return errors


def epoch(e):
    return int(parse_ts(e["timestamp"]).timestamp())


def detect(data):
    """data: {source: [events]} -> {rule: set(source_ip)}"""
    res = {r: set() for r in RULES}
    # Linux
    auth = [e for e in data.get("linux_auth", []) if e.get("process") == "sshd"]
    fails = defaultdict(list)       # (ip,user) -> times
    fails_ip = defaultdict(list)    # ip -> (t,user)
    for e in sorted(auth, key=epoch):
        if e.get("outcome") == "failure":
            t = epoch(e)
            fails[(e["source_ip"], e["username"])].append(t)
            fails_ip[e["source_ip"]].append((t, e["username"]))
        elif e.get("outcome") == "success" and e.get("username") in ("root", "demo_admin"):
            res["suspicious_admin_login"].add(e["source_ip"])
    for (ip, _u), ts in fails.items():
        if any(ts[i + 4] - ts[i] <= 60 for i in range(len(ts) - 4)):
            res["ssh_bruteforce"].add(ip)
    for ip, items in fails_ip.items():
        if sliding_distinct(items, 60, 5):
            res["password_spraying"].add(ip)
    # Web
    web = defaultdict(list)
    for e in data.get("web_access", []):
        if e.get("http_method") == "POST" and e.get("url_path") == "/login" and e.get("status_code") == 401:
            web[e["source_ip"]].append(epoch(e))
    for ip, ts in web.items():
        ts.sort()
        if any(ts[i + 4] - ts[i] <= 60 for i in range(len(ts) - 4)):
            res["web_repeated_failed_login"].add(ip)
    # Firewall
    fw = defaultdict(list)
    for e in data.get("firewall", []):
        if e.get("action") == "BLOCK":
            fw[e["source_ip"]].append((epoch(e), e["destination_port"]))
    for ip, items in fw.items():
        items.sort()
        if sliding_distinct(items, 30, 3):
            res["port_scan"].add(ip)
    return res


def sliding_distinct(items, width, need):
    q, c = deque(), Counter()
    for t, v in items:
        q.append((t, v))
        c[v] += 1
        while t - q[0][0] > width:
            _, old = q.popleft()
            c[old] -= 1
            if c[old] == 0:
                del c[old]
        if len(c) >= need:
            return True
    return False


def verify_dir(d, strict=True):
    print(f"\n=== Yoxlama: {d} ===")
    data, errors = {}, []
    for s in SOURCES:
        p = os.path.join(d, FILES[s])
        if not os.path.exists(p):
            errors.append(f"fayl tapılmadı: {p}")
            continue
        evs, errs = load_events(p)
        errors += errs + validate(s, evs)
        data[s] = evs
        print(f"  {FILES[s]}: {len(evs)} event")
    _, meta = build_scenarios(parse_ts(DEFAULT_SCENARIO_TIME))
    expected = {r: {m["ip"] for m in meta if r in m["detects"]} for r in RULES}
    negatives = {r: {m["ip"] for m in meta if r in m["not_detects"]} for r in RULES}
    found = detect(data)
    for r in RULES:
        missing = expected[r] - found[r]
        false_pos = negatives[r] & found[r]
        extra = found[r] - expected[r]
        if missing:
            errors.append(f"{r}: gözlənilən IP aşkarlanmadı {sorted(missing)}")
        if false_pos:
            errors.append(f"{r}: negative ssenari yanlış aşkarlandı {sorted(false_pos)}")
        if strict and extra:
            errors.append(f"{r}: gözlənilməyən IP-lər aşkarlandı {sorted(extra)}")
        status = "OK" if not (missing or false_pos or (strict and extra)) else "XƏTA"
        note = f" (mövcud datasetdən əlavə IP: {len(extra)})" if (extra and not strict) else ""
        print(f"  [{status}] {r}: aşkarlanan={sorted(found[r] & expected[r])}{note}")
    if errors:
        print("  Xətalar:")
        for e in errors[:20]:
            print("   -", e)
        if len(errors) > 20:
            print(f"   ... və daha {len(errors) - 20} xəta")
        return False
    print("  Nəticə: bütün yoxlamalar uğurludur.")
    return True


# --------------------------------------------------------------------------
# Baseline ölçməsi
# --------------------------------------------------------------------------
def measure_dir(d):
    rows = []
    for s in SOURCES:
        p = os.path.join(d, FILES[s])
        size = os.path.getsize(p)
        n, tmin, tmax = 0, None, None
        with open(p, encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                n += 1
                t = epoch(json.loads(line))
                tmin = t if tmin is None else min(tmin, t)
                tmax = t if tmax is None else max(tmax, t)
        window = max((tmax - tmin) if n else 1, 1)
        rows.append({"source": s, "events": n, "size": size, "window": window,
                     "eps": n / window, "gb_day": size / window * 86400 / 1e9,
                     "avg_bytes": size / n if n else 0,
                     "from": iso_epoch(tmin) if n else "-", "to": iso_epoch(tmax) if n else "-"})
    return rows


def fmt_size(b):
    return f"{b / 1024:,.1f} KB" if b < 1024 * 1024 else f"{b / 1024 / 1024:,.2f} MB"


def fmt_window(sec):
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d} ({sec:,} san)"


def baseline_table(rows, timings=None):
    head = "| Mənbə | Event sayı | Fayl ölçüsü | Ölçmə müddəti (log pəncərəsi) | EPS | GB/day (ekstrapolyasiya) |"
    sep = "| --- | ---: | ---: | --- | ---: | ---: |"
    if timings:
        head += " Generasiya vaxtı |"
        sep += " ---: |"
    lines = [head, sep]
    for r in rows:
        line = (f"| {r['source']} | {r['events']:,} | {fmt_size(r['size'])} | {fmt_window(r['window'])} "
                f"| {r['eps']:.3f} | {r['gb_day']:.4f} |")
        if timings:
            line += f" {timings[r['source']]:.2f} san |"
        lines.append(line)
    tot_e = sum(r["events"] for r in rows)
    tot_s = sum(r["size"] for r in rows)
    win = max(r["window"] for r in rows)
    line = (f"| **Cəmi** | **{tot_e:,}** | **{fmt_size(tot_s)}** | {fmt_window(win)} "
            f"| **{tot_e / win:.3f}** | **{tot_s / win * 86400 / 1e9:.4f}** |")
    if timings:
        line += f" {sum(timings.values()):.2f} san |"
    lines.append(line)
    return "\n".join(lines)


def write_baseline(path, results):
    L = ["# baseline.md - Raw log dataset ölçmələri", "",
         "Bu fayl `generate_logs.py` tərəfindən avtomatik yaradılıb. Dəyərlər yaradılmış JSONL fayllarından ölçülüb.", "",
         "## Metodologiya", "",
         "- **Event sayı** - fayldakı sətir sayı (1 sətir = 1 event).",
         "- **Fayl ölçüsü** - diskdəki JSONL faylının baytla ölçüsü.",
         "- **Ölçmə müddəti** - datasetdəki ən son və ən erkən `timestamp` arasındakı fərq (log pəncərəsi).",
         "- **EPS** = event sayı / ölçmə müddəti (saniyə).",
         "- **GB/day** = fayl ölçüsü / ölçmə müddəti x 86 400 san / 10^9 (1 GB = 10^9 bayt).",
         "- **Generasiya vaxtı** - generatorun həmin faylı yaratma müddəti (divar saatı).", ""]
    for name, (rows, timings, d) in results.items():
        L += [f"## {name} dataset", "", baseline_table(rows, timings), ""]
        if name == "small":
            L += ["> Qeyd: small dataset qısa pəncərədə (~40 dəq) çoxlu ssenari ehtiva edir, ona görə EPS və GB/day "
                  "burada yalnız formal göstəricidir; real həcm planlaması üçün **large** dataset-i istifadə edin.", ""]
    if "large" in results:
        rows = results["large"][0]
        L += ["## Həcm proqnozu (large dataset-in orta event ölçüsü əsasında)", "",
              "| Mənbə | Orta event ölçüsü (bayt) | 10 EPS -> GB/day | 100 EPS -> GB/day | 1 000 EPS -> GB/day |",
              "| --- | ---: | ---: | ---: | ---: |"]
        for r in rows:
            f = lambda eps: r["avg_bytes"] * eps * 86400 / 1e9
            L.append(f"| {r['source']} | {r['avg_bytes']:.1f} | {f(10):.3f} | {f(100):.3f} | {f(1000):.3f} |")
        L += ["", "Cədvəl hər mənbənin ayrıca həmin EPS-də işlədiyi fərziyyəsi ilə hesablanıb."]
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(L) + "\n")


# --------------------------------------------------------------------------
# expected_results.md
# --------------------------------------------------------------------------
def write_expected(path, meta, base):
    L = ["# expected_results.md - Ssenarilər və gözlənilən detection nəticələri", "",
         f"Ssenari event-ləri **eyni source_ip və vaxtlarla** həm `small/`, həm `large/` dataset-ində yerləşir "
         f"(başlanğıc: `{iso(base)}`). Hər ssenari üçün ayrıca `source_ip` istifadə olunur; "
         "positive və negative ssenarilər heç vaxt eyni IP-ni paylaşmır.", "",
         "## 1. Ssenari cədvəli", "",
         "| ID | Ssenari | Növ | Mənbə | source_ip | Vaxt (UTC) | Event | Təsvir | Gözlənilən nəticə |",
         "| --- | --- | --- | --- | --- | --- | ---: | --- | --- |"]
    for m in meta:
        L.append(f"| {m['id']} | {m['name']} | {m['kind']} | {m['source']} | `{m['ip']}` | "
                 f"{m['start']} - {m['end'][11:]} | {m['count']} | {m['detail']} | {m['expect']} |")
    L += ["", "> A1-A5 tapşırığın məcburi ssenarilərinə, W1 və F1 məcburi web/firewall ssenarilərinə uyğundur. "
          "W2, W3, F2, F3 əlavə negative ssenarilərdir (qaydaların yalnız eşiyə deyil, status_code/action/zaman "
          "şərtlərinə də baxdığını yoxlamaq üçün).", "",
          "## 2. Detection qaydaları", "", "| Qayda | Şərt |", "| --- | --- |"]
    for r, d in RULES.items():
        L.append(f"| `{r}` | {d} |")
    L += ["", "## 3. Qayda üzrə gözlənilən aşkarlanma", "",
          "| Qayda | Aşkarlanmalı IP-lər | Aşkarlanmamalı IP-lər (negative) |", "| --- | --- | --- |"]
    for r in RULES:
        pos = ", ".join(f"`{m['ip']}`" for m in meta if r in m["detects"]) or "-"
        neg = ", ".join(f"`{m['ip']}`" for m in meta if r in m["not_detects"]) or "-"
        L.append(f"| `{r}` | {pos} | {neg} |")
    L += ["", "Fon (noise) trafiki yalnız `198.51.100.0/24` və `203.0.113.0/24` aralıqlarından gəlir "
          f"(eyni IP eyni mənbədə ən azı {MIN_GAP} san fasilə ilə görünür), ona görə yuxarıdakı qaydalar "
          "fon trafikində **heç bir** alert yaratmamalıdır. Beləliklə, hər qayda üçün alert verən IP-lər yalnız "
          "3-cü cədvəldəki IP-lərdir (`generate_logs.py --verify` bunu yoxlayır).", "",
          "## 4. Maskalama (Modul B) üçün gözlənilənlər", "",
          "| Mənbə | Field | Raw logda (açıq) | Cribl-dən sonra |", "| --- | --- | --- | --- |",
          f"| linux_auth | `password_sample` | `{PASSWORD_SAMPLE}` (bütün event-lərdə) | maskalanmış olmalıdır |",
          f"| web_access | `url_query` | `{SECRET_QUERY}` (W1-W3 və fon event-lərinin bir hissəsində; bəzilərində "
          f"`{SECRET_QUERY}&session=test123`) | `token` dəyəri maskalanmış olmalıdır |", "",
          "Maskalamadan sonra da yuxarıdakı detection nəticələri dəyişməməlidir (detection itkisi = 0).", "",
          "## 5. Bu faylı yoxlama", "",
          "```bash", "python generate_logs.py --verify small", "python generate_logs.py --verify large", "```"]
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(L) + "\n")


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="SOC Modul A log generatoru")
    ap.add_argument("--out", default="output", help="çıxış qovluğu (default: output)")
    ap.add_argument("--seed", default=42, type=int, help="təkrarlana bilən nəticə üçün seed")
    ap.add_argument("--profile", choices=["small", "large", "all"], default="all")
    ap.add_argument("--scenario-time", default=DEFAULT_SCENARIO_TIME,
                    help="ilk ssenarinin başlama vaxtı, ISO 8601 UTC (default: %(default)s)")
    ap.add_argument("--linux-events", type=int, default=30000, help="large: fon linux_auth event sayı")
    ap.add_argument("--web-events", type=int, default=50000, help="large: fon web_access event sayı")
    ap.add_argument("--firewall-events", type=int, default=50000, help="large: fon firewall event sayı")
    ap.add_argument("--append-to", metavar="DIR",
                    help="mövcud dataset qovluğuna yalnız ssenari event-lərini əlavə et (köhnə loglar saxlanılır)")
    ap.add_argument("--verify", metavar="DIR", help="DIR-dəki JSONL fayllarını yoxla")
    ap.add_argument("--measure", metavar="DIR", help="DIR üçün baseline cədvəlini çap et")
    a = ap.parse_args()

    if a.verify:
        sys.exit(0 if verify_dir(a.verify, strict=True) else 1)
    if a.measure:
        print(baseline_table(measure_dir(a.measure)))
        return

    base = parse_ts(a.scenario_time)

    if a.append_to:
        os.makedirs(a.append_to, exist_ok=True)
        scen, _ = build_scenarios(base)
        for s in SOURCES:
            path = os.path.join(a.append_to, FILES[s])
            existing = set()
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    existing = {line.rstrip("\n") for line in f}
            new = [e for e in scen[s] if dumps(e) not in existing]  # təkrar işə salma dublikat yaratmır
            write_jsonl(path, new, append=True)
            print(f"{FILES[s]}: {len(new)} ssenari event-i əlavə olundu, "
                  f"{len(scen[s]) - len(new)} artıq mövcud idi (köhnə məzmun saxlanıldı)")
        print("Qeyd: əlavə olunan event-lər faylın sonundadır; Cribl timestamp üzrə emal etdiyi üçün sıra vacib deyil.")
        ok = verify_dir(a.append_to, strict=False)
        sys.exit(0 if ok else 1)

    os.makedirs(a.out, exist_ok=True)
    results, meta = {}, None

    if a.profile in ("small", "all"):
        d, meta, tm = generate_profile(
            "small", a.out, base, {"linux_auth": 14, "web_access": 16, "firewall": 14},
            base - timedelta(seconds=600), 2400, a.seed)
        results["small"] = (measure_dir(d), tm, d)
        print(f"small  -> {d}")

    if a.profile in ("large", "all"):
        start = base.replace(hour=0, minute=0, second=0)
        d, meta, tm = generate_profile(
            "large", a.out, base,
            {"linux_auth": a.linux_events, "web_access": a.web_events, "firewall": a.firewall_events},
            start, 86400, a.seed)
        results["large"] = (measure_dir(d), tm, d)
        print(f"large  -> {d}")

    write_expected(os.path.join(a.out, "expected_results.md"), meta, base)
    write_baseline(os.path.join(a.out, "baseline.md"), results)
    print("expected_results.md və baseline.md yaradıldı.")
    ok = all(verify_dir(v[2], strict=True) for v in results.values())
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
