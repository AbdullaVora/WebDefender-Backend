from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import logging
import subprocess
import random
import requests
import json
import os
import uuid


# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

app = FastAPI()

# List of proxies for PREMIUM users
PROXIES = [
    "http://127.0.0.1:9050",
    "http://proxy1.example.com:8080",
    "http://proxy2.example.com:8080"
]

# List of common User-Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/119.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Firefox/110.0",
    "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 Chrome/110.0.0.0"
]

payload_path = r"helper\payloads\dirbrute.txt"

# Dynamic Cookie Generation
def get_cookies(url):
    session = requests.Session()
    try:
        response = session.get(url)
        response.raise_for_status()
        return session.cookies.get_dict()
    except requests.RequestException as e:
        logging.warning(f"Failed to fetch cookies: {e}")
        return {}

# Proxy Management
def get_proxy(user_role):
    return random.choice(PROXIES) if user_role == 'premium' else None          

def format_dirsearch_json(raw_data, scan_info):
    formatted_data = {
        "scan_info": scan_info,
        "results": []
    }
    
    # Get results list from raw_data
    results_list = raw_data.get("results", raw_data) if isinstance(raw_data, dict) else raw_data
    
    for entry in results_list:
        formatted_data["results"].append({
            "status": entry.get("status"),
            "url": entry.get("url"),
            "redirect_to": entry.get("redirect") if entry.get("redirect") and entry.get("redirect").strip() else None,
            "content_type": entry.get("content-type"),
            "content_length": entry.get("content-length")
        })


    return formatted_data
# Function to run Dirsearch and save JSON results
async def run_dirsearch(url, wordlist=payload_path, user_role='free', delay=0.3,
                   threads=15, extensions="php,html,txt,js,css", timeouts=30, retries=3):

    user_agent = random.choice(USER_AGENTS)
    cookies = get_cookies(url)

    json_report_path = "dirsearch_report.json"

    cmd = [
        "dirsearch",
        "-u", url,
        "-w", wordlist,
        "-e", extensions,
        "-t", str(threads),
        "--random-agent",
        "--delay", str(delay),
        "--timeout", str(timeouts),
        "--retries", str(retries),
        "-r",
        "--deep-recursive",
        "--user-agent", user_agent,
        "-H", f"Referer: {url}",
        "-H", "X-Forwarded-For: 127.0.0.1",
        "-H", "Origin: https://bing.com",
        "-H", f"Cookie: {json.dumps(cookies)}",
        "--exclude-status=403,404",
        "--exclude-size=0",
        "-o", json_report_path,
        "--format=json"
    ]

    if proxy := get_proxy(user_role):
        cmd.extend(["--proxy", proxy])
        logging.info(f"[+] Premium feature enabled: Proxy rotation with {proxy}")

    try:
        logging.info(f"[+] Starting Dirsearch for {user_role.upper()} user with delay: {delay}s | UA: {user_agent}")
        subprocess.run(cmd, check=True)

        # Load and format Dirsearch JSON output
        if os.path.exists(json_report_path):
            with open(json_report_path, 'r') as file:
                raw_data = json.load(file)
                logging.info(f"Raw data type: {type(raw_data)}")
                logging.info(f"Raw data sample: {str(raw_data)[:500]}")

            scan_info = {
                "target": url,
                # "wordlist": wordlist,
                "extensions": extensions.split(","),
                "threads": threads,
                "delay": delay,
                "timeout": timeouts,
                # "user_agent": user_agent
            }

            # Format the extracted data
            formatted_data = format_dirsearch_json(raw_data, scan_info)

            # Save formatted data
            with open("formatted_report.json", "w") as json_file:
                json.dump(formatted_data, json_file, indent=4)

            logging.info(f"[✔️] Scan completed! Results saved in `formatted_report.json`.")
            logging.info(f"[+] Discovered {len(formatted_data['results'])} paths.")
            
            return formatted_data
        else:
            logging.error("[❗] Dirsearch JSON report was not generated.")
            return None

    except subprocess.CalledProcessError as e:
        logging.error(f"[❌] Error running Dirsearch: {e}")
        return None
    except FileNotFoundError:
        logging.critical("[❗] Dirsearch not found. Ensure it's installed via `pip install dirsearch`.")
        return None
    except Exception as e:
        logging.error(f"[❗] Unexpected error: {e}")
        return None