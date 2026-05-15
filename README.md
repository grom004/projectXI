# projectXI — Полная документация

> Асинхронный модульный сканер веб-уязвимостей + веб-дашборд с историей сканов  
> **Только для авторизованного тестирования**

---

## Содержание

1. [Обзор проекта](#1-обзор-проекта)
2. [Структура файлов](#2-структура-файлов)
3. [Установка](#3-установка)
4. [pentestkit.py — сканер](#4-pentestkitpy--сканер)
   - [Запуск](#41-запуск)
   - [Аргументы командной строки](#42-аргументы-командной-строки)
   - [Настройка цели](#43-настройка-цели)
   - [Модули атак](#44-модули-атак)
   - [Как работает краулер](#45-как-работает-краулер)
   - [Rate limiter](#46-rate-limiter)
   - [Отчёты](#47-отчёты)
5. [dashboard.py — веб-дашборд](#5-dashboardpy--веб-дашборд)
   - [Запуск](#51-запуск)
   - [Разделы интерфейса](#52-разделы-интерфейса)
   - [API-маршруты](#53-api-маршруты)
   - [Импорт отчётов в БД](#54-импорт-отчётов-в-бд)
   - [Live-запуск сканов через браузер](#55-live-запуск-сканов-через-браузер)
   - [База данных SQLite](#56-база-данных-sqlite)
6. [Совместная работа сканера и дашборда](#6-совместная-работа-сканера-и-дашборда)
7. [Примеры реальных сценариев](#7-примеры-реальных-сценариев)
8. [Уровни критичности находок](#8-уровни-критичности-находок)
9. [Архитектура кода](#9-архитектура-кода)
10. [Расширение и кастомизация](#10-расширение-и-кастомизация)
11. [Ограничения и важные замечания](#11-ограничения-и-важные-замечания)
12. [Зависимости](#12-зависимости)

---

## 1. Обзор проекта

PentestKit состоит из двух файлов:

| Файл | Назначение |
|---|---|
| `pentestkit.py` | CLI-сканер: обходит сайт и проверяет его на 8 типов уязвимостей, сохраняет HTML + JSON отчёты |
| `dashboard.py` | Веб-интерфейс: история всех сканов в SQLite, графики, фильтры по находкам, запуск новых сканов прямо из браузера с live-логами |

Оба файла работают независимо. Дашборд автоматически подхватывает JSON-отчёты, созданные сканером.

**Ключевые технические решения:**

- Весь HTTP — асинхронный через `aiohttp`, нет блокирующих вызовов
- Один краулер собирает все endpoint'ы сайта, затем все модули работают по этому списку параллельно
- Token-bucket rate limiter не даёт превысить заданный RPS и не триггерит WAF
- Каждый модуль — отдельный класс-наследник `BaseScanner`, добавить новый тип атаки можно за 20 строк
- Дашборд передаёт лог-строки в браузер в реальном времени через Server-Sent Events (SSE)

---

## 2. Структура файлов

```
project/
├── pentestkit.py      ← сканер (один файл, ~400 строк)
├── dashboard.py       ← дашборд Flask + SQLite (~550 строк)
├── pentestkit.db      ← база данных (создаётся автоматически)
└── reports/           ← папка отчётов (создаётся автоматически)
    ├── report_20250515_143200.html
    ├── report_20250515_143200.json
    └── ...
```

Больше никаких файлов не нужно. Все зависимости устанавливаются через pip.

---

## 3. Установка

### Требования

- Python 3.9+
- pip

### Установка зависимостей

```bash
pip install aiohttp beautifulsoup4 rich lxml flask
```

| Пакет | Нужен для |
|---|---|
| `aiohttp` | Асинхронные HTTP-запросы в сканере |
| `beautifulsoup4` | Парсинг HTML (краулер, CSRF-сканер) |
| `rich` | Цветной вывод в терминале, прогресс-бары |
| `lxml` | Быстрый HTML-парсер для BeautifulSoup |
| `flask` | Веб-сервер дашборда |

### Проверка установки

```bash
python -c "import aiohttp, bs4, rich, flask; print('OK')"
```

---

## 4. pentestkit.py — сканер

### 4.1 Запуск

**Интерактивный режим** — программа сама спросит URL:

```bash
python pentestkit.py
```

```
Введи URL цели: https://target.com
```

**С параметрами:**

```bash
python pentestkit.py --url https://target.com
```

---

### 4.2 Аргументы командной строки

| Аргумент | По умолчанию | Описание |
|---|---|---|
| `--url` | (интерактивный ввод) | Целевой URL. Если не указан — спросит в консоли |
| `--modules` | все 8 | Список модулей через пробел: `sql xss lfi ssrf csrf redirect headers overflow` |
| `--depth` | `2` | Глубина краулинга. 1 = только стартовая страница, 4 = глубокий обход |
| `--rps` | `10.0` | Максимум запросов в секунду (защита от бана) |
| `--threads` | `12` | Максимум параллельных соединений |
| `--output` | `reports` | Папка для сохранения отчётов |
| `--proxy` | нет | Прокси-сервер, например `http://127.0.0.1:8080` для Burp Suite |

**Примеры:**

```bash
# Только SQL-инъекции и XSS, глубокий краулинг
python pentestkit.py --url https://target.com --modules sql xss --depth 3

# Осторожный скан (5 RPS, чтобы не триггерить WAF)
python pentestkit.py --url https://target.com --rps 5

# Через Burp Suite для ручного анализа трафика
python pentestkit.py --url https://target.com --proxy http://127.0.0.1:8080

# Полный агрессивный скан
python pentestkit.py --url https://target.com --depth 4 --rps 20 --threads 20

# Сохранить отчёт в конкретную папку
python pentestkit.py --url https://target.com --output /home/user/pentest/results
```

---

### 4.3 Настройка цели

**Базовая цель:**
```bash
python pentestkit.py --url https://example.com
```

**Авторизованная цель** (за логином). Нужно передать Cookie сессии.  
Для этого отредактируй в коде `DEFAULT_CFG["headers"]`:

```python
DEFAULT_CFG = {
    ...
    "headers": {
        "User-Agent": "PentestKit/2.0 (authorised security testing)",
        "Cookie": "session=ВАШ_ТОКЕН_СЕССИИ; другие=куки",
        "Authorization": "Bearer ВАШ_JWT_ТОКЕН",  # для API
    },
}
```

Либо сканируй конкретный раздел за логином, передав его URL напрямую:

```bash
python pentestkit.py --url https://target.com/dashboard/admin
```

**HTTPS без валидации сертификата** — уже включено по умолчанию (`ssl=False` в TCPConnector). Самоподписанные сертификаты не блокируют скан.

---

### 4.4 Модули атак

#### `sql` — SQL Injection (Error-Based)

Что делает: подставляет SQL-payload'ы в каждый GET-параметр URL и ищет в ответе сообщения об ошибках БД.

Проверяемые payload'ы:
- `'` — простая кавычка (самый частый триггер)
- `" OR "1"="1` — boolean injection
- `' OR '1'='1'--` — комментарий после инъекции
- `1 AND 1=1--` — stacked query

Признаки уязвимости в ответе: `sql syntax`, `mysql_fetch`, `ORA-XXXX`, `sqlite_`, `pg_query`, `syntax error`, `unclosed quotation`, `ODBC SQL`, `DB2 SQL`.

Критичность: **CRITICAL**

Рекомендация: параметризованные запросы (prepared statements), ORM, запрет детальных ошибок БД в продакшне.

---

#### `xss` — Reflected XSS

Что делает: вставляет уникальный UUID-токен внутри JS-контекстных символов в параметры URL. Если токен отражается в HTML-ответе без энкодинга — уязвимость найдена.

Payload-шаблоны:
- `<script>/*TOKEN*/</script>`
- `"><img src=x onerror=/*TOKEN*/>`
- `<svg/onload=/*TOKEN*/>`
- `';/*TOKEN*/`

Использование UUID вместо `<script>alert(1)</script>` позволяет избежать ложных срабатываний и детектирования WAF.

Критичность: **HIGH**

Рекомендация: HTML-энкодировать весь пользовательский вывод, добавить Content-Security-Policy.

---

#### `lfi` — Local File Inclusion

Что делает: пробует прочитать `/etc/passwd` через path traversal в GET-параметрах.

Payload'ы:
- `../../../../etc/passwd`
- `..%2F..%2F..%2Fetc%2Fpasswd` (URL-encoded)
- `....//....//etc/passwd` (двойной обход)
- `/etc/passwd%00` (null-byte)
- `php://filter/convert.base64-encode/resource=index`

Признак успеха: в ответе есть строки типа `root:x:0:0:` или `daemon:`.

Критичность: **CRITICAL**

Рекомендация: белый список допустимых путей, никогда не передавать пользовательский ввод в `fopen()`, `include()`, `require()`.

---

#### `ssrf` — Server-Side Request Forgery

Что делает: ищет параметры с именами типа `url`, `uri`, `src`, `dest`, `redirect`, `path`, `host`, `fetch` и пробует заставить сервер обратиться к внутренним ресурсам.

Целевые внутренние адреса:
- `http://169.254.169.254/latest/meta-data/` — AWS Instance Metadata
- `http://127.0.0.1/`
- `http://localhost/`

Признаки успеха в ответе: `ami-id`, `instance-id`, `meta-data`, `computeMetadata`, `root:`, `127.0.0.1`.

Критичность: **CRITICAL**

Рекомендация: whitelist допустимых хостов, блокировка запросов к `169.254.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.

---

#### `csrf` — Cross-Site Request Forgery

Что делает: находит все POST-формы на странице через BeautifulSoup и проверяет:
1. Есть ли hidden input с именем похожим на CSRF-токен (`csrf`, `xsrf`, `token`, `_token`, `authenticity_token`, `nonce`)
2. Установлен ли `SameSite` в Set-Cookie заголовках

Если оба условия не выполнены — форма уязвима.

Критичность: **MEDIUM**

Рекомендация: криптографически случайный CSRF-токен в каждой state-changing форме, `SameSite=Strict` или `SameSite=Lax` на сессионных куках.

---

#### `redirect` — Open Redirect

Что делает: ищет параметры с именами `url`, `redirect`, `next`, `goto`, `return`, `returnto`, `dest`, `destination`, `redir`, `redirect_uri`, `continue` и пробует подставить внешний URL.

Payload'ы:
- `https://evil.com`
- `//evil.com` (protocol-relative)
- `/\evil.com` (обход проверки на `/`)

Проверяет HTTP 301/302/303/307/308 и смотрит, есть ли `evil.com` в заголовке `Location`.

Критичность: **MEDIUM**

Рекомендация: whitelist допустимых redirect-адресов, никогда не редиректить напрямую на пользовательский ввод.

---

#### `headers` — Security Headers Audit

Что делает: делает GET-запрос к корневому URL (`/`) и проверяет наличие / отсутствие заголовков безопасности.

**Отсутствующие заголовки (уязвимость):**

| Заголовок | Критичность | Что даёт |
|---|---|---|
| `Strict-Transport-Security` | HIGH | Защита от downgrade-атак, MITM |
| `Content-Security-Policy` | HIGH | Защита от XSS |
| `X-Content-Type-Options` | MEDIUM | Запрет MIME-sniffing |
| `X-Frame-Options` | MEDIUM | Защита от clickjacking |
| `Referrer-Policy` | LOW | Контроль утечки URL в Referer |
| `Permissions-Policy` | LOW | Ограничение браузерных API |

**Информационная утечка (если заголовок присутствует):**

| Заголовок | Критичность |
|---|---|
| `Server` | MEDIUM |
| `X-Powered-By` | MEDIUM |
| `X-AspNet-Version` | LOW |
| `X-AspNetMvc-Version` | LOW |

Критичность: от **LOW** до **HIGH**

---

#### `overflow` — Buffer Overflow / Large Input Probe

Что делает: отправляет в GET-параметры строки длиной 1KB, 4KB, 10KB и смотрит, возвращает ли сервер HTTP 500.

Это не реальное переполнение буфера в памяти (такое через HTTP не проверить), а тест устойчивости сервера к большому вводу: выявляет отсутствие валидации длины, нестабильность приложения.

Критичность: **HIGH** (при крэше сервера)

Рекомендация: ограничение длины ввода на уровне приложения и веб-сервера (nginx `client_max_body_size`, etc.).

---

### 4.5 Как работает краулер

Краулер — асинхронный BFS (обход в ширину) по страницам того же домена.

**Алгоритм:**

1. Стартует с переданного URL
2. Загружает страницу, парсит все `<a href="...">` через BeautifulSoup
3. Нормализует ссылки: убирает фрагменты (`#anchor`), отфильтровывает ссылки на другие домены и не-HTTP схемы (`mailto:`, `javascript:`)
4. Добавляет новые URL в очередь, помечает посещёнными
5. Повторяет до достижения `--depth`

**Параметры, влияющие на краулер:**

- `--depth 1` — только стартовая страница (быстро, мало URL)
- `--depth 2` — стартовая + все ссылки с неё (стандарт)
- `--depth 3` — + ссылки со страниц второго уровня (хорошо для больших сайтов)
- `--depth 4` — полный обход (медленно, много URL, риск бана)

**Что краулер не делает:**
- Не заполняет формы и не кликает кнопки (статический анализ ссылок)
- Не выходит за пределы домена
- Не следует за JavaScript-навигацией (только HTML `<a href>`)

---

### 4.6 Rate Limiter

Используется алгоритм **token bucket**:

- Каждую секунду в "ведро" добавляется `rps` токенов (но не более максимума)
- Каждый HTTP-запрос тратит 1 токен
- Если токенов нет — запрос ждёт (`asyncio.sleep`)

Это обеспечивает равномерный поток запросов без всплесков, что критично для обхода WAF (которые детектируют именно резкие пики).

Рекомендуемые значения `--rps`:

| Ситуация | RPS |
|---|---|
| Продакшн-сайт с WAF | 5–10 |
| Staging без WAF | 10–20 |
| Локальный тестовый сервер | 20–50 |

---

### 4.7 Отчёты

После каждого скана в папке `reports/` создаются два файла:

**HTML-отчёт** (`report_YYYYMMDD_HHMMSS.html`):
- Открывается в любом браузере без сервера
- Темная тема, карточки по каждой находке
- Сортировка по критичности (Critical → Info)
- Для каждой находки: severity-бейдж, URL, описание, evidence (фрагмент ответа), рекомендация

**JSON-отчёт** (`report_YYYYMMDD_HHMMSS.json`):
- Структурированные данные для интеграции с другими инструментами
- Импортируется автоматически в дашборд

```json
{
  "meta": {
    "target": "https://target.com",
    "timestamp": "20250515_143200",
    "elapsed": 12.4,
    "urls": 47
  },
  "findings": [
    {
      "module": "sql_injection",
      "severity": "critical",
      "title": "SQL Injection (Error-Based)",
      "url": "https://target.com/item?id='",
      "detail": "Param `id` leaks SQL error with payload: '",
      "evidence": "You have an error in your SQL syntax...",
      "recommendation": "Используй параметризованные запросы."
    }
  ]
}
```

---

## 5. dashboard.py — веб-дашборд

### 5.1 Запуск

```bash
python dashboard.py
```

Открыть в браузере: **http://127.0.0.1:5000**

При старте дашборд:
1. Создаёт `pentestkit.db` если её нет
2. Сканирует папку `reports/` и импортирует все JSON-файлы
3. Запускает Flask на `127.0.0.1:5000`

---

### 5.2 Разделы интерфейса

#### ◈ Дашборд

Главная страница с общей статистикой:

- **4 счётчика** — всего сканов, Critical находки, High находки, всего находок
- **Doughnut-диаграмма** — распределение находок по severity
- **Линейный тренд** — динамика Critical и High по последним 12 сканам
- **Таблица последних сканов** — 8 последних с быстрой ссылкой "Открыть"

#### ☰ История сканов

Полная таблица всех сканирований:

- Цель, дата/время, количество просканированных URL
- Разбивка по severity: Critical / High / Med / Low
- Кнопка **Открыть** → страница с детальными находками этого скана
- Кнопка **✕** → удалить скан и все его находки из БД

На странице находок:
- Фильтры по severity (All / Critical / High / Medium / Low / Info)
- Карточка для каждой находки: severity-бейдж, модуль, URL, описание, evidence, рекомендация

#### ▶ Новый скан

Форма запуска нового сканирования прямо из браузера:

- **URL цели** — поле ввода
- **Глубина** — выпадающий список: 1 (быстро) / 2 (стандарт) / 3 (глубоко) / 4 (макс)
- **RPS** — 5 / 10 / 20
- **Модули** — кнопки-тогглы для каждого из 8 модулей, можно включить/выключить любой
- **Кнопка "Выбрать все / снять"**

После нажатия "Запустить скан" появляется **live-лог** — строки приходят в реальном времени пока работает скан. По завершении отчёт автоматически добавляется в БД и историю.

---

### 5.3 API-маршруты

Все эндпоинты возвращают JSON.

| Метод | Путь | Описание |
|---|---|---|
| `GET` | `/` | HTML-страница дашборда |
| `GET` | `/api/stats` | Общая статистика: счётчики, распределение по severity, тренд, последние сканы |
| `GET` | `/api/scans` | Список всех сканов (до 100, сортировка по убыванию id) |
| `GET` | `/api/scans/<id>` | Один скан + все его находки |
| `DELETE` | `/api/scans/<id>` | Удалить скан и его находки |
| `POST` | `/api/run` | Запустить новый скан, возвращает `{"job_id": "..."}` |
| `GET` | `/api/run/<job_id>/stream` | SSE-поток лога для запущенного скана |

**Пример POST /api/run:**

```json
{
  "target": "https://target.com",
  "modules": ["sql", "xss", "headers"],
  "depth": 2,
  "rps": 10
}
```

**Ответ:**

```json
{"job_id": "job_1715770320000"}
```

После этого подключиться к `/api/run/job_1715770320000/stream` для получения лог-строк.

---

### 5.4 Импорт отчётов в БД

Дашборд автоматически читает папку `reports/` при каждом старте и импортирует все JSON-файлы, которых ещё нет в БД (проверка по паре `target + timestamp`).

Можно также запустить скан из CLI и потом открыть дашборд — отчёт уже будет в истории:

```bash
# Терминал 1: запустить скан
python pentestkit.py --url https://target.com

# Терминал 2: открыть/перезапустить дашборд
python dashboard.py
# → автоматически импортирует свежий JSON
```

Или если дашборд уже работает — нажать **↺ Обновить** на странице истории. Дашборд при нажатии кнопки вызывает import повторно через маршрут `/api/scans`.

---

### 5.5 Live-запуск сканов через браузер

**Техническая реализация:**

1. Браузер делает `POST /api/run` с параметрами скана
2. Сервер создаёт `queue.Queue` под уникальный `job_id` и запускает отдельный `threading.Thread`
3. Поток запускает `pentestkit.py` как subprocess через `subprocess.Popen` с `stdout=PIPE`
4. Поток построчно читает stdout subprocess'а, очищает ANSI-коды (`re.sub`) и кладёт строки в очередь
5. Браузер подключается к `GET /api/run/<job_id>/stream` — Flask генератор вычитывает очередь и отдаёт `text/event-stream`
6. JS в браузере слушает через `new EventSource(url)` и дописывает строки в log-блок
7. По окончании поток кладёт `None` в очередь — это сигнал закрыть SSE-соединение
8. После завершения subprocess'а вызывается `import_all_reports()` — новый JSON сразу попадает в БД

**Важно:** `pentestkit.py` должен лежать в той же папке что и `dashboard.py`, т.к. запуск идёт как `python pentestkit.py`.

---

### 5.6 База данных SQLite

Файл `pentestkit.db` создаётся автоматически рядом с `dashboard.py`.

**Таблица `scans`:**

| Поле | Тип | Описание |
|---|---|---|
| `id` | INTEGER PK | Автоинкремент |
| `target` | TEXT | URL цели |
| `timestamp` | TEXT | Метка времени скана |
| `elapsed` | REAL | Время выполнения в секундах |
| `n_urls` | INTEGER | Количество просканированных URL |
| `n_total` | INTEGER | Всего находок |
| `n_crit` | INTEGER | Находок Critical |
| `n_high` | INTEGER | Находок High |
| `n_med` | INTEGER | Находок Medium |
| `n_low` | INTEGER | Находок Low |
| `modules` | TEXT | Список использованных модулей |
| `source` | TEXT | `import` или `live` |

**Таблица `findings`:**

| Поле | Тип | Описание |
|---|---|---|
| `id` | INTEGER PK | Автоинкремент |
| `scan_id` | INTEGER FK | Ссылка на `scans.id` (CASCADE DELETE) |
| `module` | TEXT | Имя модуля: `sql_injection`, `xss`, и т.д. |
| `severity` | TEXT | `critical` / `high` / `medium` / `low` / `info` |
| `title` | TEXT | Заголовок находки |
| `url` | TEXT | URL где найдена уязвимость |
| `detail` | TEXT | Подробное описание |
| `evidence` | TEXT | Фрагмент HTTP-ответа |
| `recommendation` | TEXT | Рекомендация по исправлению |

Индексы: `idx_findings_scan` по `scan_id`, `idx_findings_sev` по `severity`.  
Включён `PRAGMA journal_mode=WAL` — позволяет читать БД пока идёт запись (параллельные сканы).

---

## 6. Совместная работа сканера и дашборда

**Схема полного рабочего процесса:**

```
┌─────────────────────────────────────────────────────┐
│                   Два способа сканировать            │
│                                                     │
│  Способ А: CLI                  Способ Б: Браузер   │
│  ─────────                      ──────────────────  │
│  python pentestkit.py           dashboard.py        │
│  --url https://target.com       → раздел "▶ Запуск" │
│                                 → заполнить форму   │
│                                 → нажать "Запустить"│
└───────────────┬─────────────────────────┬───────────┘
                │                         │
                ▼                         ▼
         reports/report_*.json      (тот же JSON)
                │                         │
                └──────────┬──────────────┘
                           │
                           ▼
                     pentestkit.db
                     (SQLite)
                           │
                           ▼
                  http://127.0.0.1:5000
                  ┌─────────────────────┐
                  │  ◈ Дашборд          │
                  │  ☰ История сканов   │
                  │  ▶ Новый скан       │
                  └─────────────────────┘
```

**Рекомендуемый рабочий процесс:**

```bash
# 1. Запустить дашборд (один раз, держать открытым)
python dashboard.py

# 2. Открыть http://127.0.0.1:5000 в браузере

# 3. Запустить скан — или из браузера (раздел "▶ Новый скан")
#    или из терминала:
python pentestkit.py --url https://target.com

# 4. Результаты сразу появятся в истории дашборда
```

---

## 7. Примеры реальных сценариев

### Bug Bounty — быстрый первичный скан

```bash
python pentestkit.py \
  --url https://target.com \
  --modules sql xss lfi ssrf \
  --depth 3 \
  --rps 8
```

### Проверка после деплоя (только заголовки и CSRF)

```bash
python pentestkit.py \
  --url https://myapp.com \
  --modules headers csrf \
  --depth 1 \
  --rps 20
```

### Скан с авторизацией (редактируй DEFAULT_CFG в коде)

```python
DEFAULT_CFG["headers"]["Cookie"] = "sessionid=abc123; csrftoken=xyz"
```

```bash
python pentestkit.py --url https://target.com/dashboard
```

### Интеграция с Burp Suite

```bash
python pentestkit.py \
  --url https://target.com \
  --proxy http://127.0.0.1:8080
```

Весь трафик сканера пройдёт через Burp — можно вручную анализировать запросы и повторять интересные.

### Скан локального тестового окружения

```bash
python pentestkit.py \
  --url http://localhost:8000 \
  --depth 4 \
  --rps 50 \
  --threads 30
```

---

## 8. Уровни критичности находок

| Severity | Цвет | Смысл | Примеры |
|---|---|---|---|
| **CRITICAL** | Красный | Немедленная угроза. Эксплуатируется тривиально | SQL Injection, LFI, SSRF |
| **HIGH** | Оранжевый | Серьёзная уязвимость, требует приоритетного исправления | XSS, Buffer Overflow, отсутствие HSTS/CSP |
| **MEDIUM** | Жёлтый | Уязвимость с ограниченным контекстом | CSRF, Open Redirect, X-Frame-Options |
| **LOW** | Зелёный | Незначительный риск, улучшение защиты | Referrer-Policy, Permissions-Policy |
| **INFO** | Серый | Информационная находка | Информационные утечки в заголовках |

---

## 9. Архитектура кода

### BaseScanner (pentestkit.py)

Все 8 модулей наследуют от `BaseScanner`. Базовый класс предоставляет:

```python
class BaseScanner:
    async def _acquire(self)          # получить токен из rate limiter
    async def _get(session, url)      # GET-запрос с rate limiting
    def _add(**kwargs)                # добавить Finding в список
    async def scan_url(session, url)  # переопределить в подклассе
    async def run() -> list[Finding] # запустить по всем URL, вернуть находки
```

### Добавление нового модуля (пример)

```python
class XXEScanner(BaseScanner):
    MODULE = "xxe"

    async def scan_url(self, session, url):
        # Твоя логика здесь
        payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        resp = await self._get(session, url + "?xml=" + payload)
        if resp and "root:" in await resp.text():
            self._add(
                severity="critical",
                title="XXE Injection",
                url=url,
                detail="XML External Entity injection found",
                recommendation="Отключи разрешение внешних сущностей в XML-парсере."
            )

# Зарегистрировать в словаре SCANNERS:
SCANNERS["xxe"] = XXEScanner
```

---

## 10. Расширение и кастомизация

### Добавить свои payload'ы в SQL-модуль

Найди в коде `_SQL_PAYLOADS` и добавь:

```python
_SQL_PAYLOADS = [
    ("'", "error"),
    ('" OR "1"="1', "boolean"),
    ("' OR '1'='1'--", "boolean"),
    ("1 AND 1=1--", "stacked"),
    ("' UNION SELECT NULL--", "union"),   # добавить
    ("'; WAITFOR DELAY '0:0:5'--", "time"),  # добавить
]
```

### Добавить свои паттерны в Header-сканер

```python
_REQ_HEADERS["Cross-Origin-Opener-Policy"] = ("medium", "Добавь COOP: same-origin")
_REQ_HEADERS["Cross-Origin-Resource-Policy"] = ("low", "Добавь CORP: same-origin")
```

### Изменить порт дашборда

В `dashboard.py` в конце файла:

```python
PORT = 8080   # изменить порт
```

### Разрешить доступ к дашборду с других машин в сети

```python
HOST = "0.0.0.0"   # вместо "127.0.0.1"
```

⚠️ Делать это только в изолированной тестовой среде.

---

## 11. Ограничения и важные замечания

**Технические ограничения:**

- Краулер обходит только HTML-ссылки (`<a href>`). JavaScript-роутинг (SPA — React, Vue, Angular) не обходится. Для SPA нужен headless browser (Playwright, Puppeteer).
- SQL-сканер проверяет только error-based инъекции. Blind SQL injection (time-based, boolean-based без ошибок) требует другого подхода.
- XSS-сканер находит только reflected XSS. Stored XSS не обнаруживается.
- Переполнение буфера проверяется косвенно (HTTP 500), реальный анализ памяти невозможен через HTTP.

**Правовые ограничения:**

> ⚠️ **Сканирование чужих систем без письменного разрешения владельца — уголовно наказуемо** в большинстве стран.

Инструмент предназначен исключительно для:
- Тестирования систем, которыми вы владеете
- Авторизованного пентестинга (есть письменное разрешение)
- CTF-соревнований на специально созданных для этого платформах (HackTheBox, TryHackMe, DVWA, WebGoat)

---

## 12. Зависимости

| Пакет | Версия | Назначение |
|---|---|---|
| `aiohttp` | ≥ 3.9 | Асинхронный HTTP-клиент (весь сетевой слой сканера) |
| `beautifulsoup4` | ≥ 4.12 | Парсинг HTML (краулер, CSRF-модуль) |
| `rich` | ≥ 13.0 | Красивый вывод в терминале: баннер, прогресс, таблицы |
| `lxml` | ≥ 5.0 | Быстрый HTML-парсер (бэкенд для BeautifulSoup) |
| `flask` | ≥ 3.0 | Веб-сервер дашборда |
| `sqlite3` | встроен | База данных (stdlib Python) |
| `asyncio` | встроен | Асинхронность (stdlib Python) |
| `threading` | встроен | Запуск subprocess в потоке (stdlib Python) |

**Установка одной командой:**

```bash
pip install aiohttp beautifulsoup4 rich lxml flask
```

---

# projectXI — Полная документация

> Async modular web vulnerability scanner + web dashboard with scan history  
> **For authorised testing only**

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [File Structure](#2-file-structure)
3. [Installation](#3-installation)
4. [pentestkit.py — The Scanner](#4-pentestkitpy--the-scanner)
   - [Running the Scanner](#41-running-the-scanner)
   - [Command-Line Arguments](#42-command-line-arguments)
   - [Configuring the Target](#43-configuring-the-target)
   - [Attack Modules](#44-attack-modules)
   - [How the Crawler Works](#45-how-the-crawler-works)
   - [Rate Limiter](#46-rate-limiter)
   - [Reports](#47-reports)
5. [dashboard.py — Web Dashboard](#5-dashboardpy--web-dashboard)
   - [Running the Dashboard](#51-running-the-dashboard)
   - [Interface Sections](#52-interface-sections)
   - [API Routes](#53-api-routes)
   - [Importing Reports into the DB](#54-importing-reports-into-the-db)
   - [Live Scan Launch via Browser](#55-live-scan-launch-via-browser)
   - [SQLite Database](#56-sqlite-database)
6. [Scanner and Dashboard Working Together](#6-scanner-and-dashboard-working-together)
7. [Real-World Usage Examples](#7-real-world-usage-examples)
8. [Finding Severity Levels](#8-finding-severity-levels)
9. [Code Architecture](#9-code-architecture)
10. [Extending and Customising](#10-extending-and-customising)
11. [Limitations and Important Notes](#11-limitations-and-important-notes)
12. [Dependencies](#12-dependencies)

---

## 1. Project Overview

PentestKit consists of two files:

| File | Purpose |
|---|---|
| `pentestkit.py` | CLI scanner: crawls a website and checks it for 8 vulnerability types, saves HTML + JSON reports |
| `dashboard.py` | Web interface: full scan history in SQLite, charts, finding filters, launch new scans directly from the browser with live logs |

Both files work independently. The dashboard automatically picks up JSON reports created by the scanner.

**Key technical decisions:**

- All HTTP is async via `aiohttp` — no blocking calls
- A single crawler collects all site endpoints, then all modules run against that list in parallel
- A token-bucket rate limiter prevents exceeding the configured RPS and avoids triggering WAFs
- Each module is a separate subclass of `BaseScanner` — adding a new attack type takes ~20 lines
- The dashboard streams log lines to the browser in real time via Server-Sent Events (SSE)

---

## 2. File Structure

```
project/
├── pentestkit.py      ← scanner (single file, ~400 lines)
├── dashboard.py       ← Flask + SQLite dashboard (~550 lines)
├── pentestkit.db      ← database (created automatically)
└── reports/           ← reports folder (created automatically)
    ├── report_20250515_143200.html
    ├── report_20250515_143200.json
    └── ...
```

No additional files are needed. All dependencies are installed via pip.

---

## 3. Installation

### Requirements

- Python 3.9+
- pip

### Installing Dependencies

```bash
pip install aiohttp beautifulsoup4 rich lxml flask
```

| Package | Used for |
|---|---|
| `aiohttp` | Async HTTP requests in the scanner |
| `beautifulsoup4` | HTML parsing (crawler, CSRF scanner) |
| `rich` | Coloured terminal output, progress bars |
| `lxml` | Fast HTML parser backend for BeautifulSoup |
| `flask` | Dashboard web server |

### Verify Installation

```bash
python -c "import aiohttp, bs4, rich, flask; print('OK')"
```

---

## 4. pentestkit.py — The Scanner

### 4.1 Running the Scanner

**Interactive mode** — the program will prompt for the URL:

```bash
python pentestkit.py
```

```
Enter target URL: https://target.com
```

**With arguments:**

```bash
python pentestkit.py --url https://target.com
```

---

### 4.2 Command-Line Arguments

| Argument | Default | Description |
|---|---|---|
| `--url` | (interactive prompt) | Target URL. If omitted, the tool asks in the console |
| `--modules` | all 8 | Space-separated list of modules: `sql xss lfi ssrf csrf redirect headers overflow` |
| `--depth` | `2` | Crawl depth. 1 = start page only, 4 = deep crawl |
| `--rps` | `10.0` | Maximum requests per second (prevents banning) |
| `--threads` | `12` | Maximum parallel connections |
| `--output` | `reports` | Folder for saving reports |
| `--proxy` | none | Proxy server, e.g. `http://127.0.0.1:8080` for Burp Suite |

**Examples:**

```bash
# SQL injection and XSS only, deep crawl
python pentestkit.py --url https://target.com --modules sql xss --depth 3

# Cautious scan (5 RPS to avoid triggering WAF)
python pentestkit.py --url https://target.com --rps 5

# Route through Burp Suite for manual traffic analysis
python pentestkit.py --url https://target.com --proxy http://127.0.0.1:8080

# Full aggressive scan
python pentestkit.py --url https://target.com --depth 4 --rps 20 --threads 20

# Save report to a specific folder
python pentestkit.py --url https://target.com --output /home/user/pentest/results
```

---

### 4.3 Configuring the Target

**Basic target:**
```bash
python pentestkit.py --url https://example.com
```

**Authenticated target** (behind a login). Pass the session cookie by editing `DEFAULT_CFG["headers"]` in the code:

```python
DEFAULT_CFG = {
    ...
    "headers": {
        "User-Agent": "PentestKit/2.0 (authorised security testing)",
        "Cookie": "session=YOUR_SESSION_TOKEN; other=cookies",
        "Authorization": "Bearer YOUR_JWT_TOKEN",  # for API endpoints
    },
}
```

Alternatively, point the scanner directly at the authenticated section:

```bash
python pentestkit.py --url https://target.com/dashboard/admin
```

**HTTPS without certificate validation** is enabled by default (`ssl=False` in TCPConnector). Self-signed certificates do not block the scan.

---

### 4.4 Attack Modules

#### `sql` — SQL Injection (Error-Based)

What it does: injects SQL payloads into each GET parameter and looks for database error messages in the response.

Payloads tested:
- `'` — bare single quote (most common trigger)
- `" OR "1"="1` — boolean injection
- `' OR '1'='1'--` — comment after injection
- `1 AND 1=1--` — stacked query

Vulnerability indicators in the response: `sql syntax`, `mysql_fetch`, `ORA-XXXX`, `sqlite_`, `pg_query`, `syntax error`, `unclosed quotation`, `ODBC SQL`, `DB2 SQL`.

Severity: **CRITICAL**

Recommendation: use parameterised queries (prepared statements) and an ORM; disable verbose DB errors in production.

---

#### `xss` — Reflected XSS

What it does: injects a unique UUID token wrapped in JS-context-breaking characters into URL parameters. If the token appears in the HTML response without encoding, the vulnerability is confirmed.

Payload templates:
- `<script>/*TOKEN*/</script>`
- `"><img src=x onerror=/*TOKEN*/>`
- `<svg/onload=/*TOKEN*/>`
- `';/*TOKEN*/`

Using a UUID instead of `<script>alert(1)</script>` avoids false positives and WAF detection.

Severity: **HIGH**

Recommendation: HTML-encode all user-controlled output; add a Content-Security-Policy header.

---

#### `lfi` — Local File Inclusion

What it does: attempts to read `/etc/passwd` via path traversal in GET parameters.

Payloads:
- `../../../../etc/passwd`
- `..%2F..%2F..%2Fetc%2Fpasswd` (URL-encoded)
- `....//....//etc/passwd` (double traversal)
- `/etc/passwd%00` (null-byte)
- `php://filter/convert.base64-encode/resource=index`

Success indicator: the response contains lines like `root:x:0:0:` or `daemon:`.

Severity: **CRITICAL**

Recommendation: whitelist allowed file paths; never pass user input to `fopen()`, `include()`, or `require()`.

---

#### `ssrf` — Server-Side Request Forgery

What it does: looks for parameters named `url`, `uri`, `src`, `dest`, `redirect`, `path`, `host`, `fetch`, etc., and attempts to make the server fetch internal resources.

Internal targets probed:
- `http://169.254.169.254/latest/meta-data/` — AWS Instance Metadata
- `http://127.0.0.1/`
- `http://localhost/`

Success indicators in the response: `ami-id`, `instance-id`, `meta-data`, `computeMetadata`, `root:`, `127.0.0.1`.

Severity: **CRITICAL**

Recommendation: whitelist allowed hosts; block requests to `169.254.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.

---

#### `csrf` — Cross-Site Request Forgery

What it does: finds all POST forms on the page via BeautifulSoup and checks:
1. Whether a hidden input exists with a name resembling a CSRF token (`csrf`, `xsrf`, `token`, `_token`, `authenticity_token`, `nonce`)
2. Whether `SameSite` is set in the `Set-Cookie` response headers

If both conditions are absent, the form is considered vulnerable.

Severity: **MEDIUM**

Recommendation: add a cryptographically random CSRF token to every state-changing form; set `SameSite=Strict` or `SameSite=Lax` on session cookies.

---

#### `redirect` — Open Redirect

What it does: looks for parameters named `url`, `redirect`, `next`, `goto`, `return`, `returnto`, `dest`, `destination`, `redir`, `redirect_uri`, `continue`, and attempts to inject an external URL.

Payloads:
- `https://evil.com`
- `//evil.com` (protocol-relative)
- `/\evil.com` (bypass forward-slash check)

Checks for HTTP 301/302/303/307/308 and inspects whether the `Location` header contains `evil.com`.

Severity: **MEDIUM**

Recommendation: whitelist allowed redirect destinations; never redirect directly to user-supplied input.

---

#### `headers` — Security Headers Audit

What it does: sends a GET request to the root URL (`/`) and checks for the presence or absence of security headers.

**Missing headers (vulnerability):**

| Header | Severity | Purpose |
|---|---|---|
| `Strict-Transport-Security` | HIGH | Protects against downgrade attacks and MITM |
| `Content-Security-Policy` | HIGH | Protects against XSS |
| `X-Content-Type-Options` | MEDIUM | Prevents MIME-sniffing |
| `X-Frame-Options` | MEDIUM | Protects against clickjacking |
| `Referrer-Policy` | LOW | Controls URL leakage via Referer |
| `Permissions-Policy` | LOW | Restricts browser APIs |

**Information disclosure (if the header is present):**

| Header | Severity |
|---|---|
| `Server` | MEDIUM |
| `X-Powered-By` | MEDIUM |
| `X-AspNet-Version` | LOW |
| `X-AspNetMvc-Version` | LOW |

Severity: **LOW** to **HIGH**

---

#### `overflow` — Buffer Overflow / Large Input Probe

What it does: sends strings of 1 KB, 4 KB, and 10 KB into GET parameters and checks whether the server returns HTTP 500.

This is not a real memory-level buffer overflow check (impossible over HTTP), but rather a server stability test for large input: it detects missing input length validation and application instability.

Severity: **HIGH** (if the server crashes)

Recommendation: enforce strict input length limits at the application level and in the web server config (e.g. nginx `client_max_body_size`).

---

### 4.5 How the Crawler Works

The crawler performs an async BFS (breadth-first search) over pages within the same domain.

**Algorithm:**

1. Starts from the provided URL
2. Loads the page and parses all `<a href="...">` tags via BeautifulSoup
3. Normalises links: strips fragments (`#anchor`), filters out links to other domains and non-HTTP schemes (`mailto:`, `javascript:`)
4. Adds new URLs to the queue and marks them as visited
5. Repeats until `--depth` is reached

**Parameters affecting the crawler:**

- `--depth 1` — start page only (fast, few URLs)
- `--depth 2` — start page + all linked pages (default)
- `--depth 3` — + pages linked from depth-2 pages (good for larger sites)
- `--depth 4` — full crawl (slow, many URLs, risk of being banned)

**What the crawler does NOT do:**
- Does not fill forms or click buttons (static link analysis only)
- Does not follow JavaScript-based navigation (only HTML `<a href>`)
- Does not leave the target domain

---

### 4.6 Rate Limiter

Uses a **token bucket** algorithm:

- Each second, `rps` tokens are added to the "bucket" (up to the maximum)
- Each HTTP request consumes 1 token
- If no tokens are available, the request waits (`asyncio.sleep`)

This ensures a smooth, even request flow without bursts — critical for bypassing WAFs, which detect sudden traffic spikes.

Recommended `--rps` values:

| Situation | RPS |
|---|---|
| Production site with WAF | 5–10 |
| Staging environment, no WAF | 10–20 |
| Local test server | 20–50 |

---

### 4.7 Reports

After each scan, two files are saved in the `reports/` folder:

**HTML report** (`report_YYYYMMDD_HHMMSS.html`):
- Opens in any browser without a server
- Dark theme, card layout per finding
- Sorted by severity (Critical → Info)
- Each finding card includes: severity badge, URL, description, evidence (response excerpt), recommendation

**JSON report** (`report_YYYYMMDD_HHMMSS.json`):
- Structured data for integration with other tools
- Imported automatically into the dashboard

```json
{
  "meta": {
    "target": "https://target.com",
    "timestamp": "20250515_143200",
    "elapsed": 12.4,
    "urls": 47
  },
  "findings": [
    {
      "module": "sql_injection",
      "severity": "critical",
      "title": "SQL Injection (Error-Based)",
      "url": "https://target.com/item?id='",
      "detail": "Param `id` leaks SQL error with payload: '",
      "evidence": "You have an error in your SQL syntax...",
      "recommendation": "Use parameterised queries (prepared statements)."
    }
  ]
}
```

---

## 5. dashboard.py — Web Dashboard

### 5.1 Running the Dashboard

```bash
python dashboard.py
```

Open in browser: **http://127.0.0.1:5000**

On startup, the dashboard:
1. Creates `pentestkit.db` if it does not exist
2. Scans the `reports/` folder and imports all JSON files
3. Starts Flask on `127.0.0.1:5000`

---

### 5.2 Interface Sections

#### ◈ Dashboard

Main overview page:

- **4 stat counters** — total scans, Critical findings, High findings, total findings
- **Doughnut chart** — finding distribution by severity
- **Line trend chart** — Critical and High dynamics across the last 12 scans
- **Recent scans table** — last 8 scans with a quick "Open" link

#### ☰ Scan History

Full table of all scans:

- Target, date/time, number of URLs scanned
- Breakdown by severity: Critical / High / Med / Low
- **Open** button → detailed findings page for that scan
- **✕** button → delete the scan and all its findings from the DB

On the findings page:
- Filters by severity (All / Critical / High / Medium / Low / Info)
- Card for each finding: severity badge, module, URL, description, evidence, recommendation

#### ▶ New Scan

Form to launch a new scan directly from the browser:

- **Target URL** — text input
- **Depth** — dropdown: 1 (fast) / 2 (standard) / 3 (deep) / 4 (max)
- **RPS** — 5 / 10 / 20
- **Modules** — toggle buttons for each of the 8 modules, individually enable/disable
- **Select all / deselect all** button

After clicking "Run Scan", a **live log** appears — lines stream in real time while the scan runs. On completion, the report is automatically added to the DB and history.

---

### 5.3 API Routes

All endpoints return JSON.

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Dashboard HTML page |
| `GET` | `/api/stats` | Overall stats: counters, severity distribution, trend, recent scans |
| `GET` | `/api/scans` | List of all scans (up to 100, descending by id) |
| `GET` | `/api/scans/<id>` | Single scan + all its findings |
| `DELETE` | `/api/scans/<id>` | Delete a scan and its findings |
| `POST` | `/api/run` | Start a new scan; returns `{"job_id": "..."}` |
| `GET` | `/api/run/<job_id>/stream` | SSE log stream for a running scan |

**Example POST /api/run:**

```json
{
  "target": "https://target.com",
  "modules": ["sql", "xss", "headers"],
  "depth": 2,
  "rps": 10
}
```

**Response:**

```json
{"job_id": "job_1715770320000"}
```

Then connect to `/api/run/job_1715770320000/stream` to receive log lines.

---

### 5.4 Importing Reports into the DB

The dashboard automatically reads the `reports/` folder on every startup and imports all JSON files not already in the DB (checked by the `target + timestamp` pair).

You can also run a CLI scan and then open the dashboard — the report will already be in the history:

```bash
# Terminal 1: run the scan
python pentestkit.py --url https://target.com

# Terminal 2: open / restart the dashboard
python dashboard.py
# → automatically imports the fresh JSON
```

If the dashboard is already running, click **↺ Refresh** on the history page.

---

### 5.5 Live Scan Launch via Browser

**Technical implementation:**

1. Browser sends `POST /api/run` with scan parameters
2. Server creates a `queue.Queue` under a unique `job_id` and starts a `threading.Thread`
3. The thread launches `pentestkit.py` as a subprocess via `subprocess.Popen` with `stdout=PIPE`
4. The thread reads subprocess stdout line by line, strips ANSI codes (`re.sub`), and puts lines into the queue
5. Browser connects to `GET /api/run/<job_id>/stream` — Flask generator reads the queue and yields `text/event-stream`
6. Browser JS listens via `new EventSource(url)` and appends lines to the log block in real time
7. When the thread finishes, it puts `None` into the queue — this signals the SSE connection to close
8. After the subprocess ends, `import_all_reports()` is called — the new JSON is immediately stored in the DB

**Important:** `pentestkit.py` must be in the same folder as `dashboard.py`, since the launch command is `python pentestkit.py`.

---

### 5.6 SQLite Database

The file `pentestkit.db` is created automatically next to `dashboard.py`.

**Table `scans`:**

| Field | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Auto-increment |
| `target` | TEXT | Target URL |
| `timestamp` | TEXT | Scan timestamp |
| `elapsed` | REAL | Execution time in seconds |
| `n_urls` | INTEGER | Number of URLs scanned |
| `n_total` | INTEGER | Total findings |
| `n_crit` | INTEGER | Critical findings |
| `n_high` | INTEGER | High findings |
| `n_med` | INTEGER | Medium findings |
| `n_low` | INTEGER | Low findings |
| `modules` | TEXT | List of modules used |
| `source` | TEXT | `import` or `live` |

**Table `findings`:**

| Field | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Auto-increment |
| `scan_id` | INTEGER FK | Reference to `scans.id` (CASCADE DELETE) |
| `module` | TEXT | Module name: `sql_injection`, `xss`, etc. |
| `severity` | TEXT | `critical` / `high` / `medium` / `low` / `info` |
| `title` | TEXT | Finding title |
| `url` | TEXT | URL where the vulnerability was found |
| `detail` | TEXT | Detailed description |
| `evidence` | TEXT | HTTP response excerpt |
| `recommendation` | TEXT | Remediation advice |

Indexes: `idx_findings_scan` on `scan_id`, `idx_findings_sev` on `severity`.  
`PRAGMA journal_mode=WAL` is enabled — allows reading the DB while a write is in progress (parallel scans).

---

## 6. Scanner and Dashboard Working Together

**Full workflow diagram:**

```
┌─────────────────────────────────────────────────────┐
│              Two ways to run a scan                  │
│                                                     │
│  Option A: CLI                  Option B: Browser   │
│  ─────────                      ────────────────    │
│  python pentestkit.py           dashboard.py        │
│  --url https://target.com       → "▶ New Scan"      │
│                                 → fill in the form  │
│                                 → click "Run Scan"  │
└───────────────┬─────────────────────────┬───────────┘
                │                         │
                ▼                         ▼
         reports/report_*.json      (same JSON)
                │                         │
                └──────────┬──────────────┘
                           │
                           ▼
                     pentestkit.db
                     (SQLite)
                           │
                           ▼
                  http://127.0.0.1:5000
                  ┌─────────────────────┐
                  │  ◈ Dashboard        │
                  │  ☰ Scan History     │
                  │  ▶ New Scan         │
                  └─────────────────────┘
```

**Recommended workflow:**

```bash
# 1. Start the dashboard (once, keep it running)
python dashboard.py

# 2. Open http://127.0.0.1:5000 in your browser

# 3. Run a scan — either from the browser ("▶ New Scan")
#    or from the terminal:
python pentestkit.py --url https://target.com

# 4. Results appear immediately in the dashboard history
```

---

## 7. Real-World Usage Examples

### Bug Bounty — quick initial scan

```bash
python pentestkit.py \
  --url https://target.com \
  --modules sql xss lfi ssrf \
  --depth 3 \
  --rps 8
```

### Post-deploy check (headers and CSRF only)

```bash
python pentestkit.py \
  --url https://myapp.com \
  --modules headers csrf \
  --depth 1 \
  --rps 20
```

### Authenticated scan (edit DEFAULT_CFG in the code)

```python
DEFAULT_CFG["headers"]["Cookie"] = "sessionid=abc123; csrftoken=xyz"
```

```bash
python pentestkit.py --url https://target.com/dashboard
```

### Integration with Burp Suite

```bash
python pentestkit.py \
  --url https://target.com \
  --proxy http://127.0.0.1:8080
```

All scanner traffic will pass through Burp — you can manually inspect and replay interesting requests.

### Local test environment scan

```bash
python pentestkit.py \
  --url http://localhost:8000 \
  --depth 4 \
  --rps 50 \
  --threads 30
```

---

## 8. Finding Severity Levels

| Severity | Colour | Meaning | Examples |
|---|---|---|---|
| **CRITICAL** | Red | Immediate threat; trivially exploitable | SQL Injection, LFI, SSRF |
| **HIGH** | Orange | Serious vulnerability requiring priority remediation | XSS, Buffer Overflow, missing HSTS/CSP |
| **MEDIUM** | Yellow | Vulnerability with limited but real impact | CSRF, Open Redirect, missing X-Frame-Options |
| **LOW** | Green | Minor risk; security improvement | Missing Referrer-Policy, Permissions-Policy |
| **INFO** | Grey | Informational finding | Information disclosure via response headers |

---

## 9. Code Architecture

### BaseScanner (pentestkit.py)

All 8 modules inherit from `BaseScanner`. The base class provides:

```python
class BaseScanner:
    async def _acquire(self)          # acquire a token from the rate limiter
    async def _get(session, url)      # rate-limited GET request
    def _add(**kwargs)                # append a Finding to the results list
    async def scan_url(session, url)  # override in subclass
    async def run() -> list[Finding] # run against all URLs, return findings
```

### Adding a New Module (example)

```python
class XXEScanner(BaseScanner):
    MODULE = "xxe"

    async def scan_url(self, session, url):
        payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        resp = await self._get(session, url + "?xml=" + payload)
        if resp and "root:" in await resp.text():
            self._add(
                severity="critical",
                title="XXE Injection",
                url=url,
                detail="XML External Entity injection found.",
                recommendation="Disable external entity resolution in your XML parser."
            )

# Register it in the SCANNERS dict:
SCANNERS["xxe"] = XXEScanner
```

---

## 10. Extending and Customising

### Add custom payloads to the SQL module

Find `_SQL_PAYLOADS` in the code and extend it:

```python
_SQL_PAYLOADS = [
    ("'", "error"),
    ('" OR "1"="1', "boolean"),
    ("' OR '1'='1'--", "boolean"),
    ("1 AND 1=1--", "stacked"),
    ("' UNION SELECT NULL--", "union"),          # add
    ("'; WAITFOR DELAY '0:0:5'--", "time"),      # add
]
```

### Add custom patterns to the Headers scanner

```python
_REQ_HEADERS["Cross-Origin-Opener-Policy"] = ("medium", "Add COOP: same-origin")
_REQ_HEADERS["Cross-Origin-Resource-Policy"] = ("low", "Add CORP: same-origin")
```

### Change the dashboard port

In `dashboard.py` at the bottom of the file:

```python
PORT = 8080   # change port
```

### Allow access to the dashboard from other machines on the network

```python
HOST = "0.0.0.0"   # instead of "127.0.0.1"
```

⚠️ Only do this in an isolated test environment.

---

## 11. Limitations and Important Notes

**Technical limitations:**

- The crawler only follows HTML links (`<a href>`). JavaScript routing (SPAs built with React, Vue, Angular) is not crawled. For SPAs, a headless browser is required (Playwright, Puppeteer).
- The SQL scanner only detects error-based injection. Blind SQL injection (time-based, boolean-based without visible errors) requires a different approach.
- The XSS scanner only detects reflected XSS. Stored XSS is not detected.
- Buffer overflow is checked indirectly (HTTP 500 response); real memory analysis is not possible over HTTP.

**Legal limitations:**

> ⚠️ **Scanning systems you do not own, without written permission from the owner, is a criminal offence in most jurisdictions.**

This tool is intended exclusively for:
- Testing systems you own
- Authorised penetration testing (with written permission)
- CTF competitions on platforms specifically designed for this purpose (HackTheBox, TryHackMe, DVWA, WebGoat)

---

## 12. Dependencies

| Package | Version | Purpose |
|---|---|---|
| `aiohttp` | ≥ 3.9 | Async HTTP client (entire network layer of the scanner) |
| `beautifulsoup4` | ≥ 4.12 | HTML parsing (crawler, CSRF module) |
| `rich` | ≥ 13.0 | Coloured terminal output: banner, progress, tables |
| `lxml` | ≥ 5.0 | Fast HTML parser backend for BeautifulSoup |
| `flask` | ≥ 3.0 | Dashboard web server |
| `sqlite3` | built-in | Database (Python stdlib) |
| `asyncio` | built-in | Async concurrency (Python stdlib) |
| `threading` | built-in | Subprocess execution in a thread (Python stdlib) |

**Install everything with one command:**

```bash
pip install aiohttp beautifulsoup4 rich lxml flask
```
