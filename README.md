# MTProxy Live Bot — автопостинг рабочих MTProto прокси

Каждые 30 минут бот публикует в Telegram-канал **4 живых MTProto прокси**, отобранных из нескольких постоянно обновляемых источников.

## Как это работает

1. **check** (каждые 5 мин, триггер — cron-job.org → workflow_dispatch): собирает прокси из всех источников и проверяет в два этапа:
   - **TCP-пинг** каждого (пул ×30, таймаут 5 сек) — быстрый фильтр;
   - **настоящий MTProto-хендшейк** для выживших (`mtproto_check.py`, чистый stdlib):
     - ee (FakeTLS): TLS ClientHello с SNI = домен из секрета, дайджест = HMAC-SHA256(ключ секрета) XOR метка времени, верификация ServerHello HMAC (как клиент Telegram Android), затем obfuscated2 (secure-тег DD, AES-256-CTR) и `req_pq_multi` → `resPQ` с нашим nonce;
     - dd (secure) и классика (16 байт): obfuscated2 + `req_pq_multi` → `resPQ` без TLS.
   - в `verified.json` попадают только прокси, через которые реально проходит хендшейк до Telegram DC (resPQ с нашим nonce, pq 8 байт, fingerprints) — не просто открытый порт
2. **post** (каждые 30 мин): берёт 4 живых FakeTLS-прокси, исключая использованные в последних циклах (анти-повторы через `last_used.json`), публикует пост с тегами и inline-кнопками

Самопроверка криптослоя: `python mtproto_check.py --selftest` (FIPS-197 / SP 800-38A векторы).
Проверка одного прокси: `python mtproto_check.py "tg://proxy?server=...&port=...&secret=..."`

## Источники (sources.json)

- savagebuilderfall52.github.io (Прокси Радар)
- tgmtproxy/telegram-mtproto-proxy-list (proxies.txt, FakeTLS)
- Therealwh/MTPproxyLIST (proxy_ru_verified.txt)

Добавить источник = дописать raw-URL в `sources.json`.

## Секреты

| Secret | Что |
|---|---|
| BOT_TOKEN | Токен бота от @BotFather (админ канала) |
| CHAT_ID | ID канала (-100…) |

## Канал

[t.me/mtprxtgg](https://t.me/mtprxtgg)
