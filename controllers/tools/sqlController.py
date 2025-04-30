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

SQLI_DATASET = {
    "Boolean-Based Blind SQL Injection": {"class": "Boolean-Based Blind SQL Injection", "description": "Infer database information by sending true/false conditions and observing responses.", "severity": "high", "exploitation": "Possible through crafted queries"},
    "Time-Based Blind SQL Injection": {"class": "Time-Based Blind SQL Injection", "description": "Infer database information by causing time delays in responses.", "severity": "high", "exploitation": "Possible by timing server responses"},
    "Error-Based SQL Injection": {"class": "Error-Based SQL Injection", "description": "Extract information from database errors shown in server responses.", "severity": "critical", "exploitation": "Easily exploitable when verbose errors are exposed"},
    "Union-Based SQL Injection": {"class": "Union-Based SQL Injection", "description": "Use the UNION operator to combine results from different SELECT statements.", "severity": "critical", "exploitation": "Directly exploitable if UNION is allowed"},
    "Stacked Queries SQL Injection": {"class": "Stacked Queries SQL Injection", "description": "Execute multiple SQL statements in a single query.", "severity": "critical", "exploitation": "Possible if the database allows stacked queries"},
    "Inline Queries SQL Injection": {"class": "Inline Queries SQL Injection", "description": "Inject queries that are executed inside existing database queries.", "severity": "medium", "exploitation": "Possible if input is improperly sanitized"},
    "Second Order SQL Injection": {"class": "Second Order SQL Injection", "description": "Injection payloads stored in the database are executed later in a different context.", "severity": "high", "exploitation": "Complex but possible with stored inputs"},
    "Out-of-Band SQL Injection (OOB)": {"class": "Out-of-Band SQL Injection", "description": "Retrieve data by leveraging DNS or HTTP requests to an external server.", "severity": "critical", "exploitation": "Possible if database supports external communications"},
    "Blind SQL Injection": {"class": "Blind SQL Injection", "description": "Database responses do not show data but behavior changes infer results.", "severity": "high", "exploitation": "Possible through response analysis"},
    "Heavy Query SQL Injection": {"class": "Heavy Query SQL Injection", "description": "Use heavy queries to slow down the server, detecting vulnerabilities via timing.", "severity": "medium", "exploitation": "Possible but noisy"},
    "Comment-Based SQL Injection": {"class": "Comment-Based SQL Injection", "description": "Terminate or modify queries using SQL comments like -- or /* */.", "severity": "medium", "exploitation": "Possible with improper input filtering"},
    "Batch SQL Injection": {"class": "Batch SQL Injection", "description": "Executing multiple statements in one shot, separated by semicolons.", "severity": "critical", "exploitation": "Directly exploitable if multiple statements allowed"},
    "Alternate Encodings SQL Injection": {"class": "Alternate Encodings SQL Injection", "description": "Use hex, Unicode, or URL encoding to bypass filters.", "severity": "high", "exploitation": "Possible if input normalization is missing"},
    "Double Query SQL Injection": {"class": "Double Query SQL Injection", "description": "Two queries executed to produce indirect responses for extraction.", "severity": "critical", "exploitation": "Possible with multiple query execution"},
    "Stored Procedure SQL Injection": {"class": "Stored Procedure SQL Injection", "description": "Inject into stored procedures which can have elevated privileges.", "severity": "critical", "exploitation": "Very dangerous if procedures are injectable"},
    "XPath Injection via SQL": {"class": "XPath Injection via SQL", "description": "Use SQL Injection techniques inside XML/XPath query structures.", "severity": "high", "exploitation": "Possible if XML parsers are vulnerable"},
    "NoSQL Injection": {"class": "NoSQL Injection", "description": "Injection attacks on NoSQL databases (MongoDB, etc.) using JSON-based queries.", "severity": "high", "exploitation": "Possible if NoSQL input is not sanitized"},
    "Hybrid SQL Injection": {"class": "Hybrid SQL Injection", "description": "Combines multiple techniques like error and time-based injections.", "severity": "critical", "exploitation": "Possible and often bypasses weak protections"},
    "Database Fingerprinting via SQL Injection": {"class": "Database Fingerprinting", "description": "Determine database type/version to optimize exploitation.", "severity": "medium", "exploitation": "Possible with crafted payloads"},
    "Authentication Bypass via SQL Injection": {"class": "Authentication Bypass", "description": "Log in as any user without credentials by injecting in login forms.", "severity": "critical", "exploitation": "Easily exploitable if login forms are vulnerable"}
}


URL_FILE = 'url.txt'
PAYLOAD_FILE = 'payload.txt'
OUTPUT_FILE = 'vulnerabilities.json'
SQLMAP_OUTPUT_DIR = 'sqlmap_output' 
SQLMAP_SESSION_DIR = 'sqlmap-output'
DEFAULT_TECHNIQUES = "BEUSTQ"
DEFAULT_PROXY = None  # Proxy disabled by default

vulnerabilities = []

<<<<<<< HEAD
# SQLMAP_PATH = r"helper\sqlmap-master\sqlmap.py"

SQLMAP_PATH = os.path.join('helper', 'sqlmap-master', 'sqlmap.py')
=======
SQLMAP_PATH =  "d:\WebDefender_Backend\WebDefender_API\helper\sqlmap-master\sqlmap.py"
>>>>>>> a2fde178356247913e1be4f9504c7f8ad597f496


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



async def scan_url(url, techniques, proxy, extract_db, custom_payloads=None):
    print(f"{COLORS['YELLOW']}[🔍] Scanning Target: {url}{COLORS['RESET']}", flush=True)
    print("=" * 80)

    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    if not params:
        print(f"{COLORS['RED']}[ERROR] No query parameters found in URL.{COLORS['RESET']}", flush=True)

    clear_sqlmap_sessions()

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

        if re.search(r"parameter '(.*?)' appears to be", line):
            vulnerability_found = True
            param_match = re.search(r"parameter '(.*?)' appears to be", line)
            if param_match:
                vulnerable_params.append(param_match.group(1))

        elif "Payload:" in line:
            payload_match = re.search(r"Payload: (.*)", line)
            if payload_match:
                payloads_used.append(payload_match.group(1))

        elif re.search(r"available databases \\[\\d+\\]:", line):
            db_capture_mode = True
        elif db_capture_mode and line.startswith("[*]"):
            extracted_databases.append(line.replace("[*] ", "").strip())

    process.stdout.close()
    process.wait()

    # ✅ Build basic result
    result = {
        "url": url,
        "vulnerable_parameters": vulnerable_params if vulnerable_params else None,
        "payloads": payloads_used if payloads_used else None,
        "databases": extracted_databases if extracted_databases else None,
        "logs": scan_logs
    }

    # ✅ ONLY IF vulnerability was found
    if vulnerability_found:
        sql_injection_info = SQLI_DATASET.get("Blind SQL Injection")

        if techniques:
            if "B" in techniques:
                sql_injection_info = SQLI_DATASET.get("Boolean-Based Blind SQL Injection")
            elif "T" in techniques:
                sql_injection_info = SQLI_DATASET.get("Time-Based Blind SQL Injection")
            elif "E" in techniques:
                sql_injection_info = SQLI_DATASET.get("Error-Based SQL Injection")
            elif "U" in techniques:
                sql_injection_info = SQLI_DATASET.get("Union-Based SQL Injection")
            elif "S" in techniques:
                sql_injection_info = SQLI_DATASET.get("Stacked Queries SQL Injection")
            elif "Q" in techniques:
                sql_injection_info = SQLI_DATASET.get("Inline Queries SQL Injection")

        result.update({
            "class": sql_injection_info.get("class"),
            "description": sql_injection_info.get("description"),
            "severity": sql_injection_info.get("severity"),
            "exploitation": sql_injection_info.get("exploitation")
        })

    vulnerabilities.append(result)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(vulnerabilities, f, indent=4)

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
