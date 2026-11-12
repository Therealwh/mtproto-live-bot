#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Постинг в канал @mtprxtgg: 4 живых прокси без повторов + кнопки.
- Тихий режим: с 20:00 до 12:00 МСК посты без звука (disable_notification).
- Пинг и живость: у каждого прокси «⚡ N мс · 🟢 жив Nч» (история из proxy_history.json).
- Дайджест-пост в 21:00 МСК: итоги дня + лучший прокси, закрепляется в канале
  до следующего дайджеста (старый открепляется)."""
import json, io, os, sys, time, random, datetime, urllib.request

import proxy_history

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

def is_digest_time(now):
    """Дайджест-пост: слот 21:00 МСК (крон стреляет в :00/:30)."""
    return now.hour == 21 and now.minute < 30

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

def save(p, data):
    io.open(p, "w", encoding="utf-8", newline="\n").write(json.dumps(data, ensure_ascii=False, indent=1))

def api(method, params):
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{BOT_TOKEN}/{method}",
        data=json.dumps(params).encode("utf-8"),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)

verified = load(os.path.join(ROOT, "verified.json"), {}).get("proxies", [])
last_used = load(os.path.join(ROOT, "last_used.json"), [])
used = set(u["link"] for u in last_used)
hist = load(proxy_history.path(ROOT), {})

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
digest = is_digest_time(now)
date_ru = f"{now.day} {MONTHS[now.month-1]} {now.year}"
hm = now.strftime("%H:%M")

def stat_line(p):
    """«⚡ 235 мс · 🟢 жив 14ч» — пинг хендшейка и длительность живости."""
    parts = []
    if p.get("ms") is not None:
        parts.append("⚡ %d мс" % p["ms"])
    e = hist.get(p["link"])
    parts.append(proxy_history.streak_text(e, time.time()) if e else "🟢 новая")
    return " · ".join(parts)

def proxy_block(items):
    out = []
    for i, p in enumerate(items, 1):
        out.append(f"{i}. {p['link']}")
        out.append(f"   {stat_line(p)}")
    return "\n".join(out)

status = "Сервера работают" if len(verified) >= 4 else "Часть серверов проверяется"
tail = ("⚠️ Если прокси не работает — возьмите веб-прокси по кнопке «🎁 Больше бесплатных» ниже 👇\n"
        "🌙 Тихий режим: с 20:00 до 12:00 МСК сообщения приходят без звука\n"
        f"🟢 Статус сервера: {status}\n"
        "Подключение в 1 клик — жми кнопку ниже 👇")
tags = "#mtproto #proxy #telegram #vpn #обход"

if digest:
    best = min(verified, key=lambda p: p.get("ms") if p.get("ms") is not None else 10**9)
    lr = load(os.path.join(ROOT, "last_run.json"), {})
    text = (f"📊 Итоги дня — {date_ru}\n\n"
            f"🔎 Проверено прокси: {lr.get('checked', len(verified))}\n"
            f"✅ Живых (настоящий хендшейк): {len(verified)}"
            f" · 🔐 FakeTLS: {sum(1 for p in verified if p.get('fake'))}\n"
            f"🏆 Лучший прокси дня: {stat_line(best)}\n"
            f"{best['link']}\n\n"
            f"🚀 Прокси на сейчас:\n"
            f"{proxy_block(pick)}\n\n"
            f"{tail}\n\n"
            "#дайджест " + tags)
else:
    text = (f"🚀 Рабочие MTProto прокси — {date_ru}, {hm} МСК\n\n"
            f"{proxy_block(pick)}\n\n"
            f"{tail}\n\n{tags}")

payload = {
    "chat_id": CHAT_ID,
    "text": text,
    "disable_web_page_preview": True,
    "disable_notification": quiet,
    "reply_markup": {"inline_keyboard": BUTTONS},
}
mode = "тихий (без звука)" if quiet else "обычный (со звуком)"
resp = api("sendMessage", payload)
if not resp.get("ok"):
    print("Telegram API error:", resp)
    sys.exit(1)
message_id = resp["result"]["message_id"]
print("posted: message_id", message_id, "| прокси:", len(pick),
      "| режим:", mode, "| МСК:", hm, "| дайджест:", digest)

# анти-повторы: хранить последние 32 ссылки
last_used.extend([{"link": p["link"], "at": iso_now()} for p in pick])
last_used = last_used[-32:]
save(os.path.join(ROOT, "last_used.json"), last_used)

# дайджест: открепить предыдущий, закрепить новый (до следующего дайджеста)
if digest:
    state_path = os.path.join(ROOT, "digest_state.json")
    state = load(state_path, {})
    old_mid = state.get("message_id")
    if old_mid:
        try:
            api("unpinChatMessage", {"chat_id": CHAT_ID, "message_id": old_mid})
            print("unpinned:", old_mid)
        except Exception as e:
            print("unpin не удался (не критично):", str(e)[:80])
    try:
        api("pinChatMessage", {"chat_id": CHAT_ID, "message_id": message_id,
                               "disable_notification": True})
        save(state_path, {"message_id": message_id, "date": date_ru, "at": iso_now()})
        print("pinned:", message_id)
    except Exception as e:
        print("pin не удался (нужны права бота на закрепление в канале):", str(e)[:120])
