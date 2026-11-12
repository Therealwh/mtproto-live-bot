#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Проверка прокси: тянет все источники, TCP-пингует каждый, пишет verified.json."""
import socket, json, io, os, re, time, datetime, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = os.path.dirname(os.path.abspath(__file__))
MONTHS = ["января","февраля","марта","апреля","мая","июня","июля","августа","сентября","октября","ноября","декабря"]
UA = {"User-Agent": "MTProxy-Live-checker/1.0"}
TG_RE = re.compile(r"(?:tg://|https://t\.me/)proxy\?server=([^&\s\"']+)&port=(\d+)&secret=([A-Fa-f0-9]+)")

def load_sources():
    p = os.path.join(ROOT, "sources.json")
    try:
        return json.load(io.open(p, encoding="utf-8"))
    except Exception:
        return []

def fetch(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=25) as r:
        return r.read().decode("utf-8", errors="replace")

# --- 1. сбор ссылок из всех источников ---
all_proxies = {}
src_stats = []
for url in load_sources():
    name = url.split("/")[4] if url.count("/") >= 4 else url
    try:
        data = fetch(url)
        found = [(s.strip(), int(p), sec.strip()) for s, p, sec in TG_RE.findall(data)]
        src_stats.append({"source": name, "proxies": len(found), "ok": True})
        for s, p, sec in found:
            key = (s.lower(), p, sec.lower())
            if key not in all_proxies:
                all_proxies[key] = {"server": s, "port": p, "secret": sec}
    except Exception as e:
        src_stats.append({"source": name, "proxies": 0, "ok": False, "err": str(e)[:80]})
print("собрано уникальных:", len(all_proxies), "| источники:", src_stats)

# --- 2. TCP-проверка параллельно ---
def tcp_check(pr):
    t0 = time.time()
    try:
        s = socket.create_connection((pr["server"], pr["port"]), timeout=5)
        s.close()
        ms = int((time.time() - t0) * 1000)
        return {**pr, "ms": ms}
    except Exception:
        return None

alive = []
items = list(all_proxies.values())
with ThreadPoolExecutor(max_workers=30) as ex:
    futs = {ex.submit(tcp_check, pr): pr for pr in items}
    for f in as_completed(futs):
        r = f.result()
        if r:
            alive.append(r)
alive.sort(key=lambda x: x["ms"])
verified = alive[:50]
print("живых:", len(alive), "| в verified (топ по скорости):", len(verified))

# --- 3. verified.json ---
now = datetime.datetime.utcnow() + datetime.timedelta(hours=3)
iso = now.strftime("%Y-%m-%dT%H:%M:%S+03:00")
out = {
    "updated": iso,
    "checked": len(items),
    "alive": len(alive),
    "sources": src_stats,
    "proxies": [{"server": v["server"], "port": v["port"], "secret": v["secret"], "fake": v["secret"].lower().startswith("ee"),
                 "ms": v["ms"],
                 "link": f"tg://proxy?server={v['server']}&port={v['port']}&secret={v['secret']}"} for v in verified],
}
io.open(os.path.join(ROOT, "verified.json"), "w", encoding="utf-8", newline="\n").write(json.dumps(out, ensure_ascii=False, indent=1))

# --- 4. last_run.json ---
io.open(os.path.join(ROOT, "last_run.json"), "w", encoding="utf-8", newline="\n").write(json.dumps({
    "time": iso,
    "date_ru": f"{now.day} {MONTHS[now.month-1]} {now.year}",
    "time_hm": now.strftime("%H:%M"),
    "sources_ok": sum(1 for s in src_stats if s["ok"]),
    "sources_total": len(src_stats),
    "checked": len(items),
    "alive": len(alive),
}, ensure_ascii=False, indent=1))
print("check done:", now.isoformat())
