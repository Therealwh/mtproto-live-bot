#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""История живости прокси: ведётся check.py на каждом цикле, читается post.py
для строк «🟢 жив Nч». Ключ — полная tg://ссылка (server+port+secret).

Формат записи:
  link -> {"streak_since": unix_ts, "last_seen": unix_ts, "alive_count": int, "ms": int}

Серия (streak) считается непрерывной, пока между двумя «живыми» проверками
прошло не больше STREAK_TOLERANCE секунд (допускаем пару пропущенных циклов),
иначе серия считается оборванной и начинается заново."""
import json
import io
import os
import time

STREAK_TOLERANCE = 900   # 15 мин = до 3 пропущенных 5-минутных циклов
MAX_AGE = 24 * 3600      # записи старше суток вычищаем
MAX_ENTRIES = 3000


def path(root):
    return os.path.join(root, "proxy_history.json")


def load(root):
    try:
        return json.load(io.open(path(root), encoding="utf-8"))
    except Exception:
        return {}


def save(root, hist):
    io.open(path(root), "w", encoding="utf-8", newline="\n").write(
        json.dumps(hist, ensure_ascii=False))


def update(hist, verified, now=None):
    """Обновляет историю результатами текущего цикла (verified = список dict с link/ms)."""
    now = now if now is not None else time.time()
    for v in verified:
        e = hist.get(v["link"])
        if e and now - e.get("last_seen", 0) <= STREAK_TOLERANCE:
            e["alive_count"] = e.get("alive_count", 0) + 1
        else:
            e = {"streak_since": now, "alive_count": 1}
        e["last_seen"] = now
        e["ms"] = v.get("ms")
        hist[v["link"]] = e
    prune(hist, now)


def prune(hist, now):
    """Удаляем протухшие записи; если всё ещё много — оставляем самые живучие."""
    for k in [k for k, e in hist.items() if now - e.get("last_seen", 0) > MAX_AGE]:
        del hist[k]
    if len(hist) > MAX_ENTRIES:
        keep = sorted(hist.items(), key=lambda kv: -kv[1].get("last_seen", 0))[:MAX_ENTRIES]
        hist.clear()
        hist.update(dict(keep))


def streak_hours(entry, now=None):
    """Длительность текущей серии в часах (float)."""
    now = now if now is not None else time.time()
    return max(0.0, (now - entry["streak_since"]) / 3600.0)


def streak_text(entry, now=None):
    """«🟢 жив 14ч» / «🟢 жив 1д 3ч» / «🟢 жив 45м»."""
    h = streak_hours(entry, now)
    if h >= 24:
        d, hh = divmod(int(h), 24)
        return "🟢 жив %dд %dч" % (d, hh)
    if h >= 1:
        return "🟢 жив %dч" % int(h)
    return "🟢 жив %dм" % max(1, int(h * 60))
