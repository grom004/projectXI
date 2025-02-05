# projectXI

#### ⚠ Использование этой программы для атаки на сторонние сайты без разрешения владельца является незаконным.

Программа предназначена для автоматизированного тестирования веб-приложений на наличие уязвимостей, связанных с SQL-инъекциями и переполнением буфера, а также включает инструменты для разбора журналов и скрапинга HTML-страниц.

Основные функции:

- Проверка списка веб-сайтов на наличие SQL-инъекций и уязвимостей переполнения буфера;
- Анализ журналов для поиска подозрительных SQL-запросов;
- Сканирование HTML-страницы для извлечения ссылок;
- Проведение тестирования «белого ящика», проверяя сразу несколько уязвимостей.

Запуск программы:

1. Перейти в директорию проекта: `cd /...`
  
2. Создать виртуальную среду: `python3 -m venv venv`
   
3. Активировать виртуальную среду: `source venv/bin/activate`

4. Установка необходимых библиотек:
     
      - `pip3 install requests`
      - `pip3 install beautifulsoup4`
        
5. Запуск кода: `python3 scanner.py`

---

#### ⚠ Note! Using this program to attack third-party websites is illegal without the owner's permission.

This program is designed for automated testing of web applications for SQL injection and buffer overflow vulnerabilities, and also includes tools for log parsing and HTML page scraping.

Main Functions:

- Checks a list of websites for SQL injections and buffer overflow vulnerabilities;
- Analyzes logs to find suspicious SQL queries;
- Scans HTML pages to extract links;
- Runs "White-box" testing, checking for multiple vulnerabilities at once.

Start the program:

1. Go to the project directory: `cd /...`

2. Create a virtual environment: `python3 -m venv venv`

3. Activate the virtual environment: `source venv/bin/activate`

4. Install the necessary libraries:

    - `pip3 install requests`
    - `pip3 install beautifulsoup4`

5. Run the code: `python3 scanner.py`


