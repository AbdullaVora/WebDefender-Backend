'''
Complete
'''

import requests
import json
from rich.console import Console
from rich.panel import Panel
import os
from datetime import datetime
from urllib.parse import urlparse

def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or parsed.path



def fetch_file(url, file):
    """Fetch contents of robots.txt or security.txt"""
    try:
        response = requests.get(f"{url}/{file}", timeout=5)
        if response.status_code == 200:
            return response.text.strip()
        return f"Not Found ({response.status_code})"
    except requests.RequestException as e:
        return f"Error: {str(e)}"


def scan_files(url):
    """Scan a website for robots.txt and security.txt and save results as JSON"""
    console = Console()
    console.print(Panel(f"[bold cyan]Scanning: {url}[/bold cyan]", title="Website Scanner"))

    directory = extract_domain(url)
    os.makedirs(directory, exist_ok=True)
    json_filename = os.path.join(directory, f"{directory}_SecFile_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

    robots_content = fetch_file(url, "robots.txt")
    security_content = fetch_file(url, ".well-known/security.txt")

    console.print(Panel(robots_content, title="robots.txt", expand=False))
    console.print(Panel(security_content, title="security.txt", expand=False))

    # Save results to JSON
    result = {
        "url": url,
        "robots.txt": robots_content,
        "security.txt": security_content,
    }

    with open(json_filename, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4)

    console.print(f"\n📂 [bold green]Results saved to {json_filename}[/bold green]")


def secfile(target):
    target_url = target  # Change target here
    scan_files(target_url)

