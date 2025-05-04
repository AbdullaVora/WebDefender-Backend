import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json
import os
from datetime import datetime
from urllib.parse import urlparse

def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or parsed.path



MAX_CONCURRENCY = 10
MAX_VISITED = 100  # ⬅️ Limit to 100 URLs

visited = set()
semaphore = asyncio.Semaphore(MAX_CONCURRENCY)

async def fetch(session, url):
    async with semaphore:
        try:
            async with session.get(url, timeout=10) as response:
                if response.status == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                    html = await response.text()
                    print(f"[+] Fetched: {url}")
                    return html
        except Exception as e:
            print(f"[-] Failed: {url} ({e})")
    return None

def extract_links(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    BASE_DOMAIN = extract_domain(base_url)
    links = set()
    for tag in soup.find_all('a', href=True):
        href = urljoin(base_url, tag['href'])
        parsed = urlparse(href)
        if parsed.netloc.endswith(BASE_DOMAIN):
            clean_url = parsed.scheme + "://" + parsed.netloc + parsed.path
            links.add(clean_url)
    return links

async def crawl(session, url, queue):
    if url in visited or len(visited) >= MAX_VISITED:
        return
    visited.add(url)

    html = await fetch(session, url)
    if html:
        for link in extract_links(html, url):
            if link not in visited and len(visited) < MAX_VISITED:
                await queue.put(link)

async def crawl_spider(start_url):
    queue = asyncio.Queue()
    await queue.put(start_url)

    async with aiohttp.ClientSession(headers={"User-Agent": "Mozilla/5.0"}) as session:
        pending_tasks = set()

        while (not queue.empty() or pending_tasks) and len(visited) < MAX_VISITED:
            while not queue.empty() and len(pending_tasks) < MAX_CONCURRENCY:
                url = await queue.get()
                task = asyncio.create_task(crawl(session, url, queue))
                pending_tasks.add(task)

            if pending_tasks:
                done, pending_tasks = await asyncio.wait(pending_tasks, return_when=asyncio.FIRST_COMPLETED)

    directory = extract_domain(start_url)
    os.makedirs(directory, exist_ok=True)
    filename = os.path.join(directory, f"{directory}_Crawl_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

    # Save visited URLs to JSON
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(sorted(list(visited)), f, indent=4)
    print(f"[✓] Crawled {len(visited)} URLs. Saved to visited_urls.json")


def spider(target):
    asyncio.run(crawl_spider(target))

