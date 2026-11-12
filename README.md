<div align="center">

# 🛰 MTProxy Live Bot

**Автопостинг живых MTProto-прокси в Telegram — каждый прокси проверяется настоящим MTProto-хендшейком до Telegram DC, а не просто «открытый порт»**

[![Proxy check](https://img.shields.io/github/actions/workflow/status/Therealwh/mtproto-live-bot/check.yml?branch=main&label=proxy%20check&style=flat-square)](https://github.com/Therealwh/mtproto-live-bot/actions/workflows/check.yml)
[![Post to channel](https://img.shields.io/github/actions/workflow/status/Therealwh/mtproto-live-bot/post.yml?branch=main&label=post&style=flat-square)](https://github.com/Therealwh/mtproto-live-bot/actions/workflows/post.yml)
[![Last commit](https://img.shields.io/github/last-commit/Therealwh/mtproto-live-bot/main?style=flat-square&logo=github)](https://github.com/Therealwh/mtproto-live-bot/commits/main)
[![Python](https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org)
[![stdlib only](https://img.shields.io/badge/dependencies-0-green?style=flat-square)](#)

[![✅ Живых прокси сейчас](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FTherealwh%2Fmtproto-live-bot%2Fmain%2Fverified.json&query=%24.alive&label=%E2%9C%85%20%D0%B6%D0%B8%D0%B2%D1%8B%D1%85%20%D0%BF%D1%80%D0%BE%D0%BA%D1%81%D0%B8&color=brightgreen&style=flat-square&cacheSeconds=3600)](https://raw.githubusercontent.com/Therealwh/mtproto-live-bot/main/verified.json)
[![FakeTLS проверено](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FTherealwh%2Fmtproto-live-bot%2Fmain%2Flast_run.json&query=%24.mtproto.ee&label=FakeTLS%20%D0%BF%D1%80%D0%BE%D1%88%D0%BB%D0%B8%20%D1%85%D0%B5%D0%BD%D0%B4%D1%88%D0%B5%D0%B9%D0%BA&color=blue&style=flat-square&cacheSeconds=3600)](https://raw.githubusercontent.com/Therealwh/mtproto-live-bot/main/last_run.json)

[![Telegram канал](https://img.shields.io/badge/Telegram-%40mtprxtgg-2CA5E0?style=flat-square&logo=telegram&logoColor=white)](https://t.me/mtprxtgg)
[![WEB MTProto Proxies](https://img.shields.io/badge/Telegram-%40wtfpoxy-2CA5E0?style=flat-square&logo=telegram&logoColor=white)](https://t.me/wtfpoxy)

</div>

---

## 📢 Наши каналы

| Канал | Что внутри | Подписаться |
|---|---|---|
| 🚀 **MTProto Proxy Бесплатно** | Свежие живые MTProto-прокси каждые 30 минут — подключение в 1 клик | [t.me/mtprxtgg](https://t.me/mtprxtgg) |
| 🌐 **WEB MTProto Proxies** | Бесплатный прокси и веб-прокси для обхода блокировок | [t.me/wtfpoxy](https://t.me/wtfpoxy) |

## 🤖 Наши боты

| Бот | Зачем |
|---|---|
| 🎁 [@webproxy_tgrobot](https://t.me/webproxy_tgrobot) | Больше бесплатных прокси и веб-прокси |
| 💎 [@webproxy_panel_bot](https://t.me/webproxy_panel_bot) | Приватный прокси лично для тебя |
| 🔓 [@SafeLineVPNrobot](https://t.me/SafeLineVPNrobot) | VPN с обходом белых списков |

## ⚙️ Как это работает

1. **Proxy check** — каждые 5 минут:
   - собирает прокси из источников и TCP-пингует каждый (пул ×30) — быстрый фильтр;
   - для выживших — **настоящий MTProto-хендшейк** (`mtproto_check.py`, чистый Python, 0 зависимостей):
     - **FakeTLS (ee-секреты)**: TLS ClientHello с SNI = домен из секрета и HMAC-XOR дайджестом → верификация ServerHello HMAC → obfuscated2 (AES-256-CTR) → `req_pq_multi` → `resPQ`;
     - **dd / классика**: obfuscated2 → `req_pq_multi` → `resPQ`;
   - в `verified.json` попадают **только прокси, через которые реально проходит хендшейк до Telegram DC** — сервер вернул `resPQ` с нашим nonce.

2. **Post to channel** — каждые 30 минут:
   - публикует 4 живых FakeTLS-прокси без повторов (анти-повторы на 32 ссылки) с пингом и живостью: «⚡ 240 мс · 🟢 жив 14ч»;
   - 🌙 **тихий режим: с 20:00 до 12:00 МСК посты приходят без звука** (`disable_notification`);
   - 📊 **дайджест-пост в 21:00 МСК**: итоги дня (сколько проверено/живых, лучший прокси дня) — закрепляется в канале до следующего дайджеста;
   - inline-кнопки с ботами и веб-прокси.

Самопроверка криптослоя: `python mtproto_check.py --selftest` (FIPS-197 / SP 800-38A).
Проверка одного прокси: `python mtproto_check.py "tg://proxy?server=…&port=…&secret=…"`

## 🔐 Секреты (GitHub Actions)

| Secret | Что |
|---|---|
| `BOT_TOKEN` | токен бота от @BotFather (админ канала) |
| `CHAT_ID` | ID канала (`-100…`) |

## 📂 Файлы

| Файл | Назначение |
|---|---|
| `check.py` | сбор прокси → TCP-фильтр → настоящий MTProto-хендшейк → `verified.json` |
| `mtproto_check.py` | реализация FakeTLS + obfuscated2 + MTProto-хендшейка (stdlib) |
| `post.py` | постинг в канал: ротация прокси, пинг/живость, тихий режим, дайджест с закреплением |
| `proxy_history.py` | история живости прокси (серии «🟢 жив Nч») |
| `verified.json` | пул живых прокси (случайный порядок, обновляется каждые 5 мин) |
| `proxy_history.json` | история живости — ведётся check.py, используется post.py |
| `digest_state.json` | message_id закреплённого дайджеста (для открепления следующего) |
| `last_used.json` | анти-повторы постинга (последние 32 ссылки) |
| `.github/workflows/` | `check.yml` и `post.yml` — триггерятся cron-job.org → `workflow_dispatch` |

## 🏷 Топики

`mtproto` · `mtproto-proxy` · `proxy` · `web-proxy` · `telegram` · `telegram-bot` · `faketls` · `proxy-checker` · `automation` · `python`

---

<div align="center">

**Подключайся в 1 клик — живые прокси всегда в канале 👇**

[![🚀 MTProto Proxy Бесплатно](https://img.shields.io/badge/%F0%9F%9A%80%20MTProto%20Proxy%20%D0%91%D0%B5%D1%81%D0%BF%D0%BB%D0%B0%D1%82%D0%BD%D0%BE-t.me%2Fmtprxtgg-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/mtprxtgg)
[![🌐 WEB MTProto Proxies](https://img.shields.io/badge/%F0%9F%8C%90%20WEB%20MTProto%20Proxies-t.me%2Fwtfpoxy-blue?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/wtfpoxy)

</div>
