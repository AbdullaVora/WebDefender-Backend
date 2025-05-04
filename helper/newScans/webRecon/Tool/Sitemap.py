'''
    Complete
'''

import os
import requests
import json
from rich.console import Console
from rich.panel import Panel
from xml.etree import ElementTree
from datetime import datetime
from urllib.parse import urlparse

def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or parsed.path


def fetch_sitemap(url):
    """Fetch the sitemap.xml from a website."""
    try:
        response = requests.get(f"{url}/sitemap.xml", timeout=5)
        if response.status_code == 200:
            return response.text.strip()
        return f"Not Found ({response.status_code})"
    except requests.RequestException as e:
        return f"Error: {str(e)}"


def parse_sitemap(xml_content):
    """Parse the sitemap XML and extract URLs."""
    urls = []
    try:
        root = ElementTree.fromstring(xml_content)
        for elem in root.iter("{http://www.sitemaps.org/schemas/sitemap/0.9}loc"):
            urls.append(elem.text)
    except ElementTree.ParseError:
        return ["Invalid XML Format"]
    return urls if urls else ["No URLs Found"]


def scan_sitemap(url):
    """Scan a website for sitemap.xml, display its contents, and save to JSON."""
    console = Console()
    console.print(Panel(f"[bold cyan]Scanning: {url}[/bold cyan]", title="Sitemap Scanner"))

    directory = extract_domain(url)
    os.makedirs(directory, exist_ok=True)
    json_filename = os.path.join(directory, f"{directory}_Sitemap_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

    sitemap_content = fetch_sitemap(url)

    if "Error" in sitemap_content or "Not Found" in sitemap_content:
        console.print(Panel(sitemap_content, title="Sitemap.xml", expand=False))
        result = {"url": url, "sitemap_status": sitemap_content, "sitemap_urls": []}
    else:
        urls = parse_sitemap(sitemap_content)
        console.print(Panel("\n".join(urls), title="Sitemap URLs", expand=False))
        result = {"url": url, "sitemap_status": "Found", "sitemap_urls": urls}

    # Save results to JSON with absolute path
    json_filename = os.path.abspath(json_filename)
    with open(json_filename, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4)

    console.print(f"\n📂 ✅ Results saved to {json_filename}")


def sitemap(target):
    target_url = target #"http://testphp.vulnweb.com"  # Change target here
    scan_sitemap(target_url)
