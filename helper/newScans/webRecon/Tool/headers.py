'''
Complete
'''

import requests
import http.client
import json
from rich.console import Console
from rich.table import Table
import os
from datetime import datetime
from urllib.parse import urlparse

def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or parsed.path



def get_headers_requests(url):
    """Fetch headers using requests library."""
    try:
        response = requests.get(url, timeout=5)
        return response.headers
    except requests.RequestException as e:
        return {"Error": str(e)}


def get_headers_http_client(host, path="/"):
    """Fetch hidden headers using http.client."""
    try:
        conn = http.client.HTTPSConnection(host, timeout=5)
        conn.request("GET", path)
        response = conn.getresponse()
        headers = dict(response.getheaders())
        conn.close()
        return headers
    except Exception as e:
        return {"Error": str(e)}


def scan_headers(url):
    """Scan a website for all headers, display in a table, and save as JSON."""
    console = Console()
    host = url.replace("https://", "").replace("http://", "").split("/")[0]

    headers_requests = get_headers_requests(url)
    headers_http_client = get_headers_http_client(host)

    # Merge headers, keeping all unique ones
    all_headers = {**headers_http_client, **headers_requests}

    # directory
    directory = extract_domain(url)
    os.makedirs(directory, exist_ok=True)
    json_filename = os.path.join(directory, f"{directory}_headers_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

    # Save headers to JSON file
    with open(json_filename, "w", encoding="utf-8") as f:
        json.dump({"url": url, "headers": all_headers}, f, indent=4, ensure_ascii=False)

    console.print(f"\n\033[92mHeaders saved to {json_filename}\033[0m")

    # Display headers in a table
    table = Table(title="Headers", style="bold green")
    table.add_column("Header", style="cyan", justify="right")
    table.add_column("Value", style="white", overflow="fold")

    for key, value in all_headers.items():
        table.add_row(key, value)

    console.print(table)


def headers(target):
    target_url = target  #"https://kpa.io"  # Change target here
    scan_headers(target_url)


# headers('https://kpa.io')