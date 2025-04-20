# import os
# import subprocess
# import re
# import json
# import time
# from urllib.parse import urlparse, parse_qs
# import sys
# sys.stdout.reconfigure(encoding='utf-8')

# SQLMAP_PATH = r"d:\WebDefender_Backend\WebDefender_API\helper\sqlmap-master\sqlmap.py"

# COLORS = {
#     "RED": "\033[91m", "GREEN": "\033[92m", "YELLOW": "\033[93m", "BLUE": "\033[94m", "CYAN": "\033[96m",
#     "WHITE": "\033[97m", "RESET": "\033[0m"
# }

# SQLMAP_OUTPUT_DIR = 'sqlmap_output'
# SQLMAP_SESSION_DIR = 'sqlmap-output'
# OUTPUT_FILE = 'vulnerabilities.json'

# if not os.path.exists(SQLMAP_OUTPUT_DIR):
#     os.makedirs(SQLMAP_OUTPUT_DIR)

# def clear_sqlmap_sessions():
#     if os.path.exists(SQLMAP_SESSION_DIR):
#         for file in os.listdir(SQLMAP_SESSION_DIR):
#             try:
#                 file_path = os.path.join(SQLMAP_SESSION_DIR, file)
#                 if os.path.isfile(file_path):
#                     os.remove(file_path)
#             except PermissionError:
#                 print(f"{COLORS['RED']}[ERROR] Could not delete session file: {file_path}. Retrying...{COLORS['RESET']}")
#                 time.sleep(2)
#                 os.remove(file_path)

# def scan_url(url, techniques="BEUSTQ", proxy=None, extract_db=False):
#     print(f"{COLORS['YELLOW']}[🔍] Scanning Target: {url}{COLORS['RESET']}", flush=True)
#     clear_sqlmap_sessions()

#     command = [
#         'python', SQLMAP_PATH , '-u', url, '--batch', '--random-agent', '--level=5', '--threads=5',
#         '--timeout=1', '--time-sec=1', '--fresh-queries', f'--technique={techniques}', '--flush-session', '--purge',
#         '--tamper=space2comment,charencode',
#         f'--output-dir={SQLMAP_OUTPUT_DIR}'
#     ]

#     if extract_db:
#         command.append("--dbs")

#     if proxy:
#         command.extend(["--proxy", proxy])

#     process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

#     vulnerabilities = []
#     for line in iter(process.stdout.readline, ''):
#         line = line.strip()
#         print(line, flush=True)

#         if re.search(r"parameter '(.*?)' appears to be", line):
#             param_match = re.search(r"parameter '(.*?)' appears to be", line)
#             if param_match:
#                 vulnerabilities.append({"parameter": param_match.group(1)})

#     process.stdout.close()
#     process.wait()

#     with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
#         json.dump(vulnerabilities, f, indent=4)

#     return vulnerabilities


import subprocess
import os
import re
import json
import time
import sys
import concurrent.futures
from config.database import db
from urllib.parse import urlparse, parse_qs
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

sys.stdout.reconfigure(encoding='utf-8')


COLORS = {
    "RED": "\033[91m", "GREEN": "\033[92m", "YELLOW": "\033[93m", "BLUE": "\033[94m", "CYAN": "\033[96m",
    "WHITE": "\033[97m", "RESET": "\033[0m"
}

TECHNIQUE_DESCRIPTION = {
    "B": "Boolean-based blind SQL injection - Uses conditional responses",
    "E": "Error-based SQL injection - Extracts data through database errors",
    "U": "UNION query SQL injection - Merges results from multiple queries",
    "S": "Stacked queries SQL injection - Executes multiple queries at once",
    "T": "Time-based blind SQL injection - Uses time delays to infer results",
    "Q": "Inline queries SQL injection - Executes queries within existing statements"
}

URL_FILE = 'url.txt'
PAYLOAD_FILE = 'payload.txt'
OUTPUT_FILE = 'vulnerabilities.json'
SQLMAP_OUTPUT_DIR = 'sqlmap_output' 
SQLMAP_SESSION_DIR = 'sqlmap-output'
DEFAULT_TECHNIQUES = "BEUSTQ"
DEFAULT_PROXY = None  # Proxy disabled by default

vulnerabilities = []

SQLMAP_PATH = r"d:\WebDefender_Backend\WebDefender_API\helper\sqlmap-master\sqlmap.py"


if os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
        try:
            vulnerabilities = json.load(f)
        except json.JSONDecodeError:
            vulnerabilities = []


def clear_sqlmap_sessions():
    if os.path.exists(SQLMAP_SESSION_DIR):
        for file in os.listdir(SQLMAP_SESSION_DIR):
            try:
                file_path = os.path.join(SQLMAP_SESSION_DIR, file)
                if os.path.isfile(file_path):
                    os.remove(file_path)
            except PermissionError:
                print(
                    f"{COLORS['RED']}[ERROR] Could not delete session file: {file_path}. Retrying...{COLORS['RESET']}")
                time.sleep(2)
                os.remove(file_path)



# async def scan_url(url, techniques, proxy, extract_db, custom_payloads=None):
#         print(f"{COLORS['YELLOW']}[🔍] Scanning Target: {url}{COLORS['RESET']}", flush=True)
#         print("=" * 80)

#         parsed_url = urlparse(url)
#         params = parse_qs(parsed_url.query)
#         if not params:
#             print(f"{COLORS['RED']}[ERROR] No query parameters found in URL.{COLORS['RESET']}", flush=True)

#         clear_sqlmap_sessions()
#         command = [
#             'python', SQLMAP_PATH, '-u', url, '--batch', '--random-agent', '--level=5', '--threads=5',
#             '--timeout=1', '--time-sec=1', '--fresh-queries', f'--technique={techniques}', '--flush-session', '--purge',
#             '--tamper=space2comment,charencode',
#             f'--output-dir={SQLMAP_OUTPUT_DIR}'
#         ]

#         if extract_db:
#             command.append("--dbs")

#         if proxy:
#             command.extend(["--proxy", proxy])

#         process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    
#         vulnerability_found = False
#         vulnerable_params = []
#         payloads_used = []
#         extracted_databases = []
#         db_capture_mode = False
#         scan_logs = []  # ✅ **List to store logs**

#         for line in iter(process.stdout.readline, ''):
#             line = line.strip()
#             scan_logs.append(line)  # ✅ **Store log line**
#             print(line, flush=True)

#             # Capture vulnerable parameters
#             if re.search(r"parameter '(.*?)' appears to be", line):
#                 vulnerability_found = True
#                 param_match = re.search(r"parameter '(.*?)' appears to be", line)
#                 if param_match:
#                     vulnerable_params.append(param_match.group(1))

#             # Capture payloads
#             elif "Payload:" in line:
#                 payload_match = re.search(r"Payload: (.*)", line)
#                 if payload_match:
#                     payloads_used.append(payload_match.group(1))

#             # Capture database names
#             elif re.search(r"available databases \[\d+\]:", line):
#                 db_capture_mode = True
#             elif db_capture_mode and line.startswith("[*]"):
#                 extracted_databases.append(line.replace("[*] ", "").strip())

#         process.stdout.close()
#         process.wait()

#         # Build the response object including logs
#         result = {
#             "url": url,
#             "vulnerable_parameters": vulnerable_params if vulnerable_params else None,
#             "payloads": payloads_used if payloads_used else None,
#             "databases": extracted_databases if extracted_databases else None,
#             "logs": scan_logs  # ✅ **Include logs in response**
#         }

#         if db is not None:
#             try:
#                 insert_result = await db.sql_reports.insert_one(result)  # ✅ Store MongoDB result
#                 result["_id"] = str(insert_result.inserted_id)  # ✅ Convert ObjectId to string
#                 print("[✔] Stored in MongoDB with ID:", result["_id"])
#             except Exception as e:
#                 print(f"[❌] Error saving to MongoDB: {e}")


#         return result

async def scan_url(url, techniques, proxy, extract_db, custom_payloads=None):
    print(f"{COLORS['YELLOW']}[🔍] Scanning Target: {url}{COLORS['RESET']}", flush=True)
    print("=" * 80)

    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    if not params:
        print(f"{COLORS['RED']}[ERROR] No query parameters found in URL.{COLORS['RESET']}", flush=True)

    clear_sqlmap_sessions()
    
    # Base SQLMap command
    command = [
        'python', SQLMAP_PATH, '-u', url, '--batch', '--random-agent', '--level=5', '--threads=5',
        '--timeout=1', '--time-sec=1', '--fresh-queries', f'--technique={techniques}', '--flush-session', '--purge',
        '--tamper=space2comment,charencode',
        f'--output-dir={SQLMAP_OUTPUT_DIR}'
    ]

    if extract_db:
        command.append("--dbs")

    if proxy:
        command.extend(["--proxy", proxy])

    # ✅ If custom payloads are provided, inject them into SQLMap using `--test-filter`
    if custom_payloads:
        for payload in custom_payloads:
            command.extend(["--test-filter", payload])

    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    vulnerability_found = False
    vulnerable_params = []
    payloads_used = []
    extracted_databases = []
    db_capture_mode = False
    scan_logs = []

    for line in iter(process.stdout.readline, ''):
        line = line.strip()
        scan_logs.append(line)
        print(line, flush=True)

        # Capture vulnerable parameters
        if re.search(r"parameter '(.*?)' appears to be", line):
            vulnerability_found = True
            param_match = re.search(r"parameter '(.*?)' appears to be", line)
            if param_match:
                vulnerable_params.append(param_match.group(1))

        # Capture payloads
        elif "Payload:" in line:
            payload_match = re.search(r"Payload: (.*)", line)
            if payload_match:
                payloads_used.append(payload_match.group(1))

        # Capture database names
        elif re.search(r"available databases \[\d+\]:", line):
            db_capture_mode = True
        elif db_capture_mode and line.startswith("[*]"):
            extracted_databases.append(line.replace("[*] ", "").strip())

    process.stdout.close()
    process.wait()

    # Build the response object including logs
    result = {
        "url": url,
        "vulnerable_parameters": vulnerable_params if vulnerable_params else None,
        "payloads": payloads_used if payloads_used else None,
        "databases": extracted_databases if extracted_databases else None,
        "logs": scan_logs
    }

    return result


def main():
    print(f"{COLORS['CYAN']}\n{'=' * 80}\n 🚀 SQLMAP Automated SQL Injection Scanner \n{'=' * 80}{COLORS['RESET']}")
    os.makedirs(SQLMAP_OUTPUT_DIR, exist_ok=True)

    print("\nAvailable SQL Injection Techniques:")
    for key, desc in TECHNIQUE_DESCRIPTION.items():
        print(f"  {COLORS['GREEN']}{key}{COLORS['RESET']}: {desc}")

    techniques = input("\nEnter SQL Injection techniques (default: BEUSTQ): ").strip().upper() or DEFAULT_TECHNIQUES
    proxy = input("Enter proxy (leave blank for no proxy): ").strip() or DEFAULT_PROXY
    extract_db = input("Would you like to extract database names if vulnerable? (y/n): ").strip().lower() == 'y'

    url = input("Enter a URL to scan (leave blank to scan multiple URLs from url.txt): ").strip()
    urls = [url] if url else open(URL_FILE).read().splitlines()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(lambda u: scan_url(u, techniques, proxy, extract_db), urls)

    print(f"{COLORS['GREEN']}\n{'=' * 80}\n 🎯 SCAN SUMMARY 🎯\n{'=' * 80}")
    if vulnerabilities:
        for v in vulnerabilities:
            print(f"{COLORS['CYAN']}🔹 Target: {v['url']}{COLORS['RESET']}")
            print(f"  🔸 Vulnerable Parameters: {', '.join(v['vulnerable_parameters'])}")
            print(f"  💉 Exploit Payloads: {', '.join(v['payloads'])}")
            print("-" * 80)
    else:
        print(f"{COLORS['RED']}❌ No vulnerabilities found.{COLORS['RESET']}", flush=True)
    print(f"{COLORS['GREEN']}\n{'=' * 80}\n ✅ All scans completed!{COLORS['RESET']}", flush=True)
    print(f"📂 Detailed report saved in: {OUTPUT_FILE}", flush=True)


if __name__ == "__main__":
    main()
