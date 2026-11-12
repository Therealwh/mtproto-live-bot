#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Проверка прокси в два этапа:
1. TCP-пинг всех прокси из источников (30 потоков, таймаут 5с) — быстрый фильтр.
2. Настоящая проверка MTProto-хендшейка для выживших:
   - ee (FakeTLS): TLS ClientHello с SNI из секрета + верификация ServerHello HMAC,
     затем obfuscated2 (secure-тег, AES-256-CTR с ключом из секрета) и
     req_pq_multi -> resPQ с нашим nonce (mtproto_check.py);
   - dd (secure) и классика (16 байт): obfuscated2 + req_pq_multi -> resPQ без TLS.
Прокси попадает в verified.json только если через него проходит настоящий
MTProto-хендшейк до Telegram DC (resPQ с нашим nonce), а не просто открыт порт."""
import socket, json, io, os, re, time, random, datetime, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

import mtproto_check
import proxy_history

ROOT = os.path.dirname(os.path.abspath(__file__))
MONTHS = ["января","февраля","марта","апреля","мая","июня","июля","августа","сентября","октября","ноября","декабря"]
UA = {"User-Agent": "MTProxy-Live/1.0"}
TG_RE = re.compile(r"(?:tg://|https://t\.me/)proxy\?server=([^&\s\"']+)&port=(\d+)&secret=([A-Za-z0-9_-]+)")

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

# --- 2. TCP-проверка параллельно (30 потоков, таймаут 5с) ---
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
print("TCP-живых:", len(alive))

# --- 3. настоящий MTProto-чек (FakeTLS для ee, obfuscated2 для dd/классики) ---
def deep_check(pr):
    r = mtproto_check.check_proxy(pr["server"], pr["port"], pr["secret"], timeout=8)
    if r["ok"]:
        return {**pr, "ms": r["ms"], "check": r["check"]}
    return None

verified = []
mtproto_stats = {"ee": [0, 0], "dd": [0, 0], "classic": [0, 0], "bad": 0}
def deep_stats(pr):
    parsed = mtproto_check.parse_secret(pr["secret"])
    return parsed[0] if parsed else "bad"

with ThreadPoolExecutor(max_workers=40) as ex:
    futs = {ex.submit(deep_check, pr): pr for pr in alive}
    for f in as_completed(futs):
        pr = futs[f]
        kind = deep_stats(pr)
        r = f.result()
        if kind == "bad":
            mtproto_stats["bad"] += 1
        elif r:
            mtproto_stats[kind][0] += 1
            verified.append(r)
        else:
            mtproto_stats[kind][1] += 1
random.shuffle(verified)  # весь пул в случайном порядке
print("MTProto-проверка: ee ok/fail=%d/%d dd ok/fail=%d/%d classic ok/fail=%d/%d плохих секретов=%d" % (
    mtproto_stats["ee"][0], mtproto_stats["ee"][1],
    mtproto_stats["dd"][0], mtproto_stats["dd"][1],
    mtproto_stats["classic"][0], mtproto_stats["classic"][1],
    mtproto_stats["bad"]))
print("живых (настоящий хендшейк):", len(verified))

# история живости: серии «🟢 жив Nч» для постов (proxy_history.json)
hist = proxy_history.load(ROOT)
proxy_history.update(hist, verified)
proxy_history.save(ROOT, hist)

# --- 4. verified.json ---
now = datetime.datetime.utcnow() + datetime.timedelta(hours=3)
iso = now.strftime("%Y-%m-%dT%H:%M:%S+03:00")
out = {
    "updated": iso,
    "checked": len(items),
    "tcp_alive": len(alive),
    "alive": len(verified),
    "sources": src_stats,
    "proxies": [{"server": v["server"], "port": v["port"], "secret": v["secret"],
                 "fake": v["secret"].lower().startswith("ee"), "check": v["check"], "ms": v["ms"],
                 "link": f"tg://proxy?server={v['server']}&port={v['port']}&secret={v['secret']}"} for v in verified],
}
io.open(os.path.join(ROOT, "verified.json"), "w", encoding="utf-8", newline="\n").write(json.dumps(out, ensure_ascii=False, indent=1))

# --- 5. last_run.json ---
io.open(os.path.join(ROOT, "last_run.json"), "w", encoding="utf-8", newline="\n").write(json.dumps({
    "time": iso,
    "date_ru": f"{now.day} {MONTHS[now.month-1]} {now.year}",
    "time_hm": now.strftime("%H:%M"),
    "sources_ok": sum(1 for s in src_stats if s["ok"]),
    "sources_total": len(src_stats),
    "checked": len(items),
    "tcp_alive": len(alive),
    "alive": len(verified),
    "mtproto": {k: (v[0] if isinstance(v, list) else v) for k, v in mtproto_stats.items()},
}, ensure_ascii=False, indent=1))
print("check done:", now.isoformat())
