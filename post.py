#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Постинг в канал @mtprxtgg: 4 живых прокси без повторов + кнопки.
Тихий режим: с 20:00 до 12:00 МСК посты отправляются без звука
(disable_notification), чтобы не тревожить подписчиков ночью."""
import json, io, os, sys, time, random, datetime, urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
MONTHS = ["января","февраля","марта","апреля","мая","июня","июля","августа","сентября","октября","ноября","декабря"]
BOT_TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = os.environ["CHAT_ID"]

def msk_now():
    """Московское время: МСК = UTC+3 круглый год (перехода на летнее время нет),
    поэтому utcnow + 3 часа — всегда точное МСК."""
    return datetime.datetime.utcnow() + datetime.timedelta(hours=3)

def iso_now():
    return msk_now().strftime("%Y-%m-%dT%H:%M:%S+03:00")

def is_quiet_hours(now):
    """Тихий режим 20:00–11:59 МСК включительно."""
    return now.hour >= 20 or now.hour < 12

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

ee = [p for p in verified if p.get("fake") and p["link"] not in used]  # только FakeTLS
if len(ee) >= 4:
    candidates = ee
else:
    candidates = [p for p in verified if p["link"] not in used]
if len(candidates) < 4:
    candidates = verified[:]  # всё уже использовали — сбрасываем ротацию
pick = random.sample(candidates, 4)

now = msk_now()
quiet = is_quiet_hours(now)
date_ru = f"{now.day} {MONTHS[now.month-1]} {now.year}"
hm = now.strftime("%H:%M")

lines = "\n".join(f"{i}. {p['link']}" for i, p in enumerate(pick, 1))
status = "Сервера работают" if len(verified) >= 4 else "Часть серверов проверяется"
text = (f"🚀 Рабочие MTProto прокси — {date_ru}, {hm} МСК\n\n"
        f"{lines}\n\n"
        "⚠️ Если прокси не работает — возьмите веб-прокси по кнопке «🎁 Больше бесплатных» ниже 👇\n"
        "🌙 Тихий режим: с 20:00 до 12:00 МСК сообщения приходят без звука\n"
        f"🟢 Статус сервера: {status}\n"
        "Подключение в 1 клик — жми кнопку ниже 👇\n\n"
        "#mtproto #proxy #telegram #vpn #обход")

payload = {
    "chat_id": CHAT_ID,
    "text": text,
    "disable_web_page_preview": True,
    "disable_notification": quiet,
    "reply_markup": {"inline_keyboard": BUTTONS},
}
mode = "тихий (без звука)" if quiet else "обычный (со звуком)"
req = urllib.request.Request(
    f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json"})
with urllib.request.urlopen(req, timeout=20) as r:
    resp = json.load(r)
if not resp.get("ok"):
    print("Telegram API error:", resp)
    sys.exit(1)
print("posted: message_id", resp["result"]["message_id"], "| прокси:", len(pick),
      "| режим:", mode, "| МСК:", hm)
if quiet:
    print("тихий режим активен (20:00-12:00 МСК) — disable_notification=true")

# анти-повторы: хранить последние 32 ссылки
last_used.extend([{"link": p["link"], "at": iso_now()} for p in pick])
last_used = last_used[-32:]
io.open(os.path.join(ROOT, "last_used.json"), "w", encoding="utf-8", newline="\n").write(
    json.dumps(last_used, ensure_ascii=False, indent=1))
