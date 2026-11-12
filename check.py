#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Проверка прокси через Telethon: реальный MTProto-хендшейк через каждый прокси.
connect() через прокси = прокси РЕАЛЬНО работает (не просто порт открыт)."""
import asyncio, json, io, os, sys, time, urllib.request, re, datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
MONTHS = ["января","февраля","марта","апреля","мая","июня","июля","августа","сентября","октября","ноября","декабря"]
API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]
UA = {"User-Agent": "MTProxy-Live/1.0"}
TG_RE = re.compile(r"(?:tg://|https://t\.me/)proxy\?server=([^&\s\"']+)&port=(\d+)&secret=([A-Fa-f0-9]+)")

def fetch_sources():
    sources = json.load(io.open(os.path.join(ROOT, "sources.json"), encoding="utf-8"))
    all_p = {}
    stats = []
    for url in sources:
        name = url.split("/")[4]
        try:
            req = urllib.request.Request(url, headers=UA)
            data = urllib.request.urlopen(req, timeout=25).read().decode("utf-8", errors="replace")
            found = [(s, int(p), sec) for s, p, sec in TG_RE.findall(data)]
            stats.append({"source": name, "proxies": len(found), "ok": True})
            for s, p, sec in found:
                key = (s.lower(), p, sec.lower())
                if key not in all_p:
                    all_p[key] = {"server": s, "port": p, "secret": sec}
        except Exception as e:
            stats.append({"source": name, "proxies": 0, "ok": False, "err": str(e)[:60]})
    return list(all_p.values()), stats

async def main():
    proxies, stats = fetch_sources()
    print("собрано уникальных:", len(proxies))

    import socket
    from concurrent.futures import ThreadPoolExecutor

    def tcp(pr):
        try:
            s = socket.create_connection((pr["server"], pr["port"]), timeout=5)
            s.close()
            return pr
        except Exception:
            return None
    alive = []
    with ThreadPoolExecutor(max_workers=40) as ex:
        for r in ex.map(tcp, proxies):
            if r: alive.append(r)
    print("TCP-alive:", len(alive))

    from telethon import TelegramClient, connection
    from telethon.sessions import StringSession

    sem = asyncio.Semaphore(6)
    results = []

    async def deep(pr):
        async with sem:
            proxy = {
                "proxy_type": connection.ConnectionTcpMTProxyRandomizedIntermediate,
                "addr": pr["server"], "port": pr["port"], "secret": pr["secret"],
            }
            t0 = time.time()
            client = TelegramClient(StringSession(), API_ID, API_HASH, proxy=proxy)
            try:
                await asyncio.wait_for(client.connect(), timeout=15)
                ms = int((time.time() - t0) * 1000)
                ok = client.is_connected()
                await client.disconnect()
                if ok:
                    return {**pr, "handshake": True, "ms": ms}
            except Exception:
                pass
            try: await client.disconnect()
            except Exception: pass
            return None

    # приоритет FakeTLS (ee) — выживают при DPI
    alive.sort(key=lambda p: (1 if p["secret"].lower().startswith("ee") else 0, len(p["secret"])))  # dd первее — Telethon умеет только dd
    batch = alive[:60]
    for i in range(0, len(batch), 6):
        chunk = batch[i:i+6]
        rs = await asyncio.gather(*[deep(p) for p in chunk])
        got = [r for r in rs if r]
        results.extend(got)
        print(f"прогресс: {min(i+6, len(batch))}/{min(len(batch), 60)} | прошло: {len(got)}")

    results.sort(key=lambda x: (0 if x["secret"].lower().startswith("ee") else 1, x["ms"]))
    verified = results[:50]

    now = datetime.datetime.utcnow() + datetime.timedelta(hours=3)
    iso = now.strftime("%Y-%m-%dT%H:%M:%S+03:00")
    out = {
        "updated": iso,
        "tcp_alive": len(alive),
        "handshake_verified": len(results),
        "proxies": [{"server": v["server"], "port": v["port"], "secret": v["secret"],
                     "fake": v["secret"].lower().startswith("ee"), "ms": v["ms"],
                     "link": f"tg://proxy?server={v['server']}&port={v['port']}&secret={v['secret']}"} for v in verified],
    }
    io.open(os.path.join(ROOT, "verified.json"), "w", encoding="utf-8", newline="\n").write(
        json.dumps(out, ensure_ascii=False, indent=1))
    io.open(os.path.join(ROOT, "last_run.json"), "w", encoding="utf-8", newline="\n").write(
        json.dumps({"time": iso, "date_ru": f"{now.day} {MONTHS[now.month-1]} {now.year}",
                    "time_hm": now.strftime("%H:%M"), "tcp_alive": len(alive),
                    "verified": len(results)}, ensure_ascii=False, indent=1))
    print("ИТОГ: хендшейк-проверено:", len(results), "| в verified:", len(verified))

asyncio.run(main())
