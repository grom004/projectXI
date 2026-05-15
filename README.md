# projectXI

#### ⚠ Внимание! Использование этой программы для атаки на сторонние сайты является незаконным.

Программа предназначена для автоматизированного тестирования веб-приложений на наличие уязвимостей, связанных с SQL-инъекциями и переполнением буфера, а также включает инструменты для разбора журналов и скрапинга HTML-страниц.

Основные функции:

- Проверка списка веб-сайтов на наличие SQL-инъекций и уязвимостей переполнения буфера;
- Анализ журналов для поиска подозрительных SQL-запросов;
- Сканирование HTML-страницы для извлечения ссылок;
- Проведение тестирования «белого ящика», проверяя сразу несколько уязвимостей.

Запуск программы:

1. Перейти в директорию проекта: `cd /dir_name`
  
2. Создать виртуальную среду: `python3 -m venv venv`
   
3. Активировать виртуальную среду: `source venv/bin/activate`

4. Установка необходимых библиотек:
     
      - `pip3 install requests`
      - `pip3 install beautifulsoup4`
        
5. Запуск кода: `python3 scanner.py`

---

#### ⚠ Note! Using this program to attack third-party websites is illegal.

This program is designed for automated testing of web applications for SQL injection and buffer overflow vulnerabilities, and also includes tools for log parsing and HTML page scraping.

Main Functions:

- Checks a list of websites for SQL injections and buffer overflow vulnerabilities;
- Analyzes logs to find suspicious SQL queries;
- Scans HTML pages to extract links;
- Runs "White-box" testing, checking for multiple vulnerabilities at once.

Start the program:

1. Go to the project directory: `cd /dir_name`

2. Create a virtual environment: `python3 -m venv venv`

3. Activate the virtual environment: `source venv/bin/activate`

4. Install the necessary libraries:

    - `pip3 install requests`
    - `pip3 install beautifulsoup4`

5. Run the code: `python3 scanner.py`


# PentestKit — Полная документация

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


