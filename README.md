# MTProxy Live Bot — автопостинг рабочих MTProto прокси

Каждые 30 минут бот публикует в Telegram-канал **4 живых MTProto прокси**, отобранных из нескольких постоянно обновляемых источников.

## Как это работает

1. **check** (каждые 5 мин, триггер — cron-job.org → workflow_dispatch): собирает прокси из всех источников, TCP-проверяет каждый (пул ×30, таймаут 5 сек), топ-50 по скорости пишет в `verified.json`
2. **post** (каждые 30 мин): берёт 4 живых, исключая использованные в последних циклах (анти-повторы через `last_used.json`), публикует пост с тегами и inline-кнопками

## Источники (sources.json)

- Argh94/Proxy-List (MTProto.txt)
- tgmtproxy/telegram-mtproto-proxy-list (proxies.txt, FakeTLS)
- SoliSpirit/mtproto (all_proxies.txt)
- suryadev-sm/free-mtproto-proxy-list
- Therealwh/MTPproxyLIST (proxy_ru_verified.txt)

Добавить источник = дописать raw-URL в `sources.json`.

## Секреты

| Secret | Что |
|---|---|
| BOT_TOKEN | Токен бота от @BotFather (админ канала) |
| CHAT_ID | ID канала (-100…) |

## Канал

[t.me/mtprxtgg](https://t.me/mtprxtgg)
