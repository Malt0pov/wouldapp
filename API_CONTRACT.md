# WouldApp API contract (v2) — внутренний документ для правок

Сервер: `127.0.0.1:3005`, только JSON API. Новый `server.js` и новый `index.html` пишутся
параллельно по этому контракту. **Не отклоняться от него.**

## 0. Токен

`GET /` отдаёт `index.html`, в котором сервер заменяет строку `__WOULDAPP_TOKEN__`
на одноразовый токен текущего запуска. В `<head>` обязана быть метка:

```html
<meta name="wouldapp-token" content="__WOULDAPP_TOKEN__">
```

Все `/api/*` требуют заголовок `X-WouldApp-Token: <токен>`. Без/с чужим токеном —
`401 {"success":false,"error":"unauthorized"}`.
Сервер дополнительно проверяет `Host` (только `127.0.0.1:3005` / `localhost:3005`) и
`Origin` (отсутствует или `http://127.0.0.1:3005`, `http://localhost:3005`), POST — только
`Content-Type: application/json`. Фронтенд всегда ходит через `apiFetch`, см. §7.

## 1. GET /api/status

```json
{
  "success": true,
  "running": true,
  "mode": "proxy",                 // "proxy" | "tun"
  "uptimeSeconds": 42,
  "killSwitch": false,
  "blocked": false,                // true = kill switch сработал, трафик заблокирован
  "settings": {
    "dns": "google",               // google | cloudflare | quad9 | adguard
    "mode": "proxy",
    "killSwitch": false,
    "autoConnect": false,
    "autoStart": false,
    "sound": true
  },
  "traffic": { "downBytes": 0, "upBytes": 0 },
  "logs": ["[12:00:00] ..."]
}
```

## 2. GET /api/traffic

Реальные байты из sing-box (Clash API). `{ "success": true, "downBytes": 123, "upBytes": 456, "connections": 3 }`.
Если не подключено — нули.

## 3. POST /api/connect

```json
{ "outbound": { "type": "vless", "server": "...", "server_port": 443, "...": "..." },
  "mode": "proxy",
  "killSwitch": false }
```

Ответ: `{ "success": true, "result": { "running": true, "mode": "proxy", "pid": 123, "note": "..." } }`.
`result.mode` — **фактический** режим: если запрошен `tun`, а прав администратора нет,
сервер возвращает `success:false` и `error` человеческим текстом с «администратор» (см. §5).

## 4. POST /api/disconnect

`{ "success": true, "disconnected": true }`. Восстанавливает системный прокси из бэкапа.

## 5. Ошибки

`{ "success": false, "error": "текст для пользователя" }`, HTTP 4xx/5xx.
Особые случаи: `unauthorized` (401), `tun_requires_admin` (403, error содержит
«Требуются права администратора»), `invalid_outbound` (400).

## 6. GET/POST /api/parse, /api/ping, /api/check-ip, /api/settings

- `POST /api/parse {link}` → `{success, count, nodes:[{name, outbound, rawLink}], data}`.
- `POST /api/ping {servers:[{id, server, port}]}` →
  `{success, results:[{id, ping: 23|null}]}`, ping = реальный TCP connect (мс), 2000 мс таймаут.
- `GET /api/check-ip` → `{success, ip, country, countryCode, city, isp, proxied}` —
  реальная проверка через туннель по HTTPS.
- `GET /api/settings` → `{success, settings:{...}}`.
- `POST /api/settings {partial}` → `{success, settings:{...}}`. Меняет `dns`, `mode`,
  `killSwitch`, `autoConnect`, `autoStart`, `sound`. Применяется к следующему подключению;
  `autoStart` сервер применяет сразу (HKCU Run).

## 7. Фронтенд: обязательный хелпер

```js
const WA_TOKEN = document.querySelector('meta[name="wouldapp-token"]')?.content || '';
async function apiFetch(path, opts = {}) {
  const headers = Object.assign({ 'X-WouldApp-Token': WA_TOKEN }, opts.body ? { 'Content-Type': 'application/json' } : {}, opts.headers || {});
  const r = await fetch(path, { ...opts, headers });
  if (r.status === 401) { showSnackbar('Сессия истекла — перезапустите WouldApp', 'error'); throw new Error('unauthorized'); }
  return r;
}
```

Все существующие `fetch('/api/...')` заменяются на `apiFetch('/api/...')`.
Тело всегда `JSON.stringify(...)`; разбор — `await resp.json()`.

## 8. Обязательные требования к UI

1. **Статус всегда берётся с сервера**: опрос `GET /api/status` раз в 1000 мс.
   Если `running` стало `false`, а UI показывал «Подключено» — переключить UI в «Отключено»
   и показать snackbar «Туннель прерван». Если `blocked` — показать статус
   «Трафик заблокирован (Kill Switch)».
2. **Реальная телеметрия**: скорость/график — из `/api/traffic` (дельта байт между опросами),
   время сессии — из `uptimeSeconds`, а не локальный таймер с нуля. Никаких `Math.random()`
   в скоростях, пингах и трафике.
3. **Реальный пинг**: `testAllPings()` → `POST /api/ping` с реальными `server`/`server_port`
   из `outbound`; узлы без `outbound` не пингуются (`—` вместо числа).
4. **Мок-серверы удалить**: `DEFAULT_SERVERS` больше нет. Начальное состояние — пустой список
   и empty-state «Добавьте ключ или подписку» + кнопка импорта. Из localStorage грузятся только
   реальные узлы (с `outbound`).
5. **Никаких плацебо-настроек**. Оставить/сделать работающими: режим (`mode`), DNS (`dns`),
   Kill Switch (`killSwitch`), автоподключение (`autoConnect`), автозапуск (`autoStart`),
   звук. Удалить из UI: «Сворачивать при закрытии» (трей веб-страница не умеет).
   Все настройки читаются/пишутся через `/api/settings` (для `dns/mode/killSwitch/autoConnect/autoStart`)
   и localStorage (только оформление/звук), не выдумывать.
6. **Отключение**: сначала `await apiFetch('/api/disconnect')`, и только по успешному ответу
   менять UI на «Отключено»; при ошибке — snackbar и оставить состояние «Подключено».
7. **Кнопка питания блокируется на время `connecting`** (флаг `busy`), повторные клики игнорируются.
8. **TUN**: если сервер вернул ошибку про администратора — snackbar с текстом ошибки и
   переключение селектора режима на «Системный прокси», без тихого фолбэка.
9. **Смена узла при активном подключении**: переподключать через `/api/connect` с новым outbound
   (сначала `disconnect` не нужен — сервер сам переключит без утечки), показывать «Переключение узла…».
10. **Логи**: терминал можно выделять/копировать (`user-select: text` для терминала, textarea, input,
    IP-адреса). Остальной интерфейс — без выделения.
11. **Иконки шрифтом**: `<link>` на Google Fonts оставить как fallback, но добавить локальные
    `@font-face` на `/assets/material-symbols.woff2` и `/assets/roboto-*.woff2` (их положит
    серверная часть); `font-display: block`. Если локальные файлы отсутствуют — работает CDN.
12. **Безопасность**: имена узлов/флаги/пинги вставлять через `escapeHtml` (с экранированием
    кавычек), никаких `onclick` со вставкой пользовательских строк, только безопасные id.
13. **Порт узла**: в списке серверов показывать реальный `outbound.server_port`, а не `:443`.
14. `refreshPublicIp()` — вызывать при загрузке, после connect/disconnect и по кнопке; snackbar
    только по кнопке/смене состояния, не на каждое обновление.
15. Не трогать визуальный стиль, CSS-токены, классы M3, звук, анимации — только логика и
    перечисленные HTML-правки.
