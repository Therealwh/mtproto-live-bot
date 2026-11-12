#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Постинг в канал @mtprxtgg: 4 живых прокси без повторов + кнопки."""
import json, io, os, sys, time, random, datetime, urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
MONTHS = ["января","февраля","марта","апреля","мая","июня","июля","августа","сентября","октября","ноября","декабря"]
BOT_TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = os.environ["CHAT_ID"]

def iso_now():
    return (datetime.datetime.utcnow() + datetime.timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%S+03:00")
BUTTONS = [
    [{"text": "🎁 Больше бесплатных", "url": "tg://resolve?domain=webproxy_tgrobot"}],
    [{"text": "💎 Приватный прокси", "url": "tg://resolve?domain=webproxy_panel_bot"}],
    [{"text": "🔓 VPN с обходом белых списков", "url": "tg://resolve?domain=SafeLineVPNrobot"}],
]

def load(p, default):
    try:
        return json.load(io.open(p, encoding="utf-8"))
    except Exception:
        return default

verified = load(os.path.join(ROOT, "verified.json"), {}).get("proxies", [])
last_used = load(os.path.join(ROOT, "last_used.json"), [])
used = set(u["link"] for u in last_used)

if len(verified) < 4:
    print("SKIP: живых прокси меньше 4 — пост не публикуем")
    sys.exit(0)

candidates = [p for p in verified if p["link"] not in used]
ee = [p for p in candidates if p.get("fake")]  # FakeTLS — выживает при DPI
if len(ee) >= 4:
    candidates = ee
if len(candidates) < 4:
    candidates = verified[:]  # всё уже использовали — сбрасываем ротацию
pick = random.sample(candidates, 4)

now = datetime.datetime.utcnow() + datetime.timedelta(hours=3)
date_ru = f"{now.day} {MONTHS[now.month-1]} {now.year}"
hm = now.strftime("%H:%M")

lines = "\n".join(f"{i}. {p['link']}" for i, p in enumerate(pick, 1))
status = "Сервера работают" if len(verified) >= 4 else "Часть серверов проверяется"
text = (f"🚀 Рабочие MTProto прокси — {date_ru}, {hm} МСК\n\n"
        f"{lines}\n\n"
        f"🟢 Статус сервера: {status}\n"
        f"Подключение в 1 клик — жми кнопку ниже 👇\n\n"
        f"#mtproto #proxy #telegram #vpn #обход")

payload = {
    "chat_id": CHAT_ID,
    "text": text,
    "disable_web_page_preview": True,
    "reply_markup": {"inline_keyboard": BUTTONS},
}
req = urllib.request.Request(
    f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json"})
with urllib.request.urlopen(req, timeout=20) as r:
    resp = json.load(r)
if not resp.get("ok"):
    print("Telegram API error:", resp)
    sys.exit(1)
print("posted: message_id", resp["result"]["message_id"], "| прокси:", len(pick))

# анти-повторы: хранить последние 32 ссылки
last_used.extend([{"link": p["link"], "at": iso_now()} for p in pick])
last_used = last_used[-32:]
io.open(os.path.join(ROOT, "last_used.json"), "w", encoding="utf-8", newline="\n").write(
    json.dumps(last_used, ensure_ascii=False, indent=1))
