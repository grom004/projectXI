import re
import logging
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

# Setting up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# SQL Injection: test payloads
SQL_PAYLOADS = [
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR '1'='1' --",
    '" OR "1"="1" --',
    "1 OR 1=1"
]

# Test payloads for buffer overflow
BUFFER_OVERFLOW_PAYLOADS = [
    "A" * 1000,
    "B" * 2000,
    "C" * 3000,
    "D" * 3000,
]

# Proxy settings
PROXY = None

def check_sql_injection(url):
    """Checks the URL for SQL injection vulnerabilities."""
    vulnerable = False
    for payload in SQL_PAYLOADS:
        target_url = f"{url}?id={payload}"
        try:
            response = requests.get(target_url, proxies=PROXY, timeout=5)
            if "SQL syntax" in response.text or "database error" in response.text:
                logging.warning(f"SQL injection vulnerability found at: {target_url}")
                vulnerable = True
        except requests.RequestException as e:
            logging.error(f"Error connecting to {target_url}: {e}")
    return vulnerable

def check_buffer_overflow(url):
    """Checks the URL for buffer overflow vulnerabilities."""
    vulnerable = False
    for payload in BUFFER_OVERFLOW_PAYLOADS:
        target_url = f"{url}?input={payload}"
        try:
            response = requests.get(target_url, proxies=PROXY, timeout=5)
            if response.status_code == 500 or "overflow" in response.text.lower():
                logging.warning(f"Buffer overflow vulnerability found at: {target_url}")
                vulnerable = True
        except requests.RequestException as e:
            logging.error(f"Error connecting to {target_url}: {e}")
    return vulnerable

def parse_logs(file_path):
    """Parses the log file to extract information about potential attacks."""
    try:
        with open(file_path, 'r') as log_file:
            for line in log_file:
                if re.search(r"(SELECT|INSERT|DELETE|UPDATE).*WHERE", line, re.IGNORECASE):
                    logging.info(f"Suspicious activity in log: {line.strip()}")
                else:
                    logging.debug(f"Log processed: {line.strip()}")
    except FileNotFoundError:
        logging.error(f"Log file not found: {file_path}")
    except Exception as e:
        logging.error(f"Error parsing logs: {e}")

def parse_html(url):
    """Parses the HTML page to extract links."""
    try:
        response = requests.get(url, proxies=PROXY, timeout=5)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        links = [a['href'] for a in soup.find_all('a', href=True)]
        logging.info(f"Found {len(links)} links on the page {url}")
        return links
    except requests.RequestException as e:
        logging.error(f"Error connecting to {url}: {e}")
        return []
    except Exception as e:
        logging.error(f"Error parsing HTML: {e}")
        return []

def white_box_testing():
    """White-box testing method."""
    logging.info("Starting white-box testing.")

    # Test data
    test_cases = [
        ("http://example.com/item", check_sql_injection, "SQL Injection"),
        ("http://example.com/item", check_buffer_overflow, "Buffer Overflow"),
        ("server_logs.txt", parse_logs, "Log Parsing"),
        ("http://example.com", parse_html, "HTML Parsing")
    ]

    for test_input, test_function, test_name in test_cases:
        try:
            logging.info(f"Testing: {test_name} with input: {test_input}")
            result = test_function(test_input)
            if result:
                logging.info(f"Test {test_name} completed successfully: {result}")
            else:
                logging.info(f"Test {test_name} completed: No vulnerabilities found.")
        except Exception as e:
            logging.error(f"Error in {test_name} test: {e}")

def scan_with_threads(urls, check_function):
    """Runs the scan using multiple threads."""
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(check_function, url): url for url in urls}
        for future in futures:
            url = futures[future]
            try:
                result = future.result()
                if result:
                    logging.info(f"Vulnerability found at {url}")
                else:
                    logging.info(f"No vulnerabilities found at {url}")
            except Exception as e:
                logging.error(f"Error scanning {url}: {e}")

if __name__ == "__main__":
    # Example 1: SQL Injection Check
    test_urls = [
        "http://example.com/item?id=1",
        "http://testsite.com/query",
        "http://vulnerable-site.com/check"
    ]
    logging.info("Starting multi-threaded SQL injection check.")
    scan_with_threads(test_urls, check_sql_injection)

    # Example 2: Buffer Overflow Check
    logging.info("Starting multi-threaded buffer overflow check.")
    scan_with_threads(test_urls, check_buffer_overflow)

    # Example 3: Log Parsing
    log_file_path = "server_logs.txt"
    parse_logs(log_file_path)

    # Example 4: HTML Parsing
    page_url = "http://example.com"
    links = parse_html(page_url)
    for link in links:
        logging.info(f"Found link: {link}")

    # Example 5: White-box Testing
    white_box_testing()