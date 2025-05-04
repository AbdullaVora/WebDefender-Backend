import requests
import json
import socket
import asyncio
import aiohttp
import re
import time
import folium
from datetime import datetime
from geopy.geocoders import Nominatim
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from urllib.parse import urlparse
import os



console = Console()

WAF_SIGNATURES = {
    "Cloudflare": [r'cloudflare', r'__cfduid'],
    "AWS Shield": [r'aws-shield'],
    "Imperva": [r'imperva'],
    "F5 Big-IP": [r'big-ip'],
    "Barracuda": [r'barracuda'],
    "Sucuri": [r'sucuri'],
    "Palo Alto": [r'paloalto'],
    "Akamai": [r'akamai'],
    "Fortinet": [r'fortinet'],
    "Citrix": [r'citrix'],
    "DenyAll": [r'denyall'],
    "NetScaler": [r'netscaler'],
    "ModSecurity": [r'modsecurity'],
    "StackPath": [r'stackpath'],
    "Incapsula": [r'incapsula'],
    "Reblaze": [r'reblaze'],
    "Wallarm": [r'wallarm'],
    "Ergon": [r'ergon'],
    "PowerCDN": [r'powercdn'],
    "DDoS-Guard": [r'ddos-guard'],
    "ArvanCloud": [r'arvancloud'],
    "BitNinja": [r'bitninja'],
    "Varnish": [r'varnish'],
    "Grey Wizard": [r'grey wizard'],
}

SERVER_SIGNATURES = {
    "Apache": [r'apache'],
    "Nginx": [r'nginx'],
    "IIS": [r'microsoft-iis'],
    "LiteSpeed": [r'litespeed'],
    "Caddy": [r'caddy'],
    "Tomcat": [r'tomcat'],
    "Gunicorn": [r'gunicorn'],
    "OpenResty": [r'openresty'],
    "Jetty": [r'jetty'],
    "Express": [r'express'],
    "Node.js": [r'node\.js'],
    "Envoy": [r'envoy'],
    "Cherokee": [r'cherokee'],
    "Lighttpd": [r'lighttpd'],
    "Træfik": [r'traefik'],
    "IBM WebSphere": [r'websphere'],
    "Oracle WebLogic": [r'weblogic'],
    "Resin": [r'resin'],
    "Zeus": [r'zeus'],
    "Roxen": [r'roxen'],
}

def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or parsed.path



async def get_ip(domain):
    ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    if ip_pattern.match(domain):
        return domain

    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return "Unknown IP"

async def get_geo_info(ip):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://ipinfo.io/{ip}/json", timeout=10) as response:
                data = await response.json()
                city = data.get("city", "Unknown City")
                region = data.get("region", "Unknown Region")
                isp = data.get("org", "Unknown ISP")

                geolocator = Nominatim(user_agent="geoapi")
                location = geolocator.geocode(f"{city}, {region}")
                latitude, longitude = (location.latitude, location.longitude) if location else (None, None)

                return city, region, isp, latitude, longitude
    except Exception:
        return "Unknown City", "Unknown Region", "Unknown ISP", None, None

def detect_waf(headers):
    for waf, patterns in WAF_SIGNATURES.items():
        if any(re.search(pattern, str(value), re.IGNORECASE) for pattern in patterns for value in headers.values()):
            return waf
    return "No WAF or Unknown"

def detect_server(headers):
    for server, patterns in SERVER_SIGNATURES.items():
        if any(re.search(pattern, str(value), re.IGNORECASE) for pattern in patterns for value in headers.values()):
            return server
    return "Unknown Server"

async def scan_target(session, url):
    parsed_url = urlparse(url).netloc or url
    ip_address = await get_ip(parsed_url)
    if ip_address == "Unknown IP":
        return {"Target URL": url, "Error": "Invalid domain or IP address"}

    if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip_address):
        url = f"http://{ip_address}"

    try:
        async with session.get(url, timeout=10) as response:
            waf = detect_waf(response.headers)
            server_info = detect_server(response.headers)
            city, region, isp, latitude, longitude = await get_geo_info(ip_address)

            data = {
                "Target URL": parsed_url,
                "IP Information": {
                    "IP Address": ip_address,
                    "Location": f"{city}, {region}",
                    "Latitude": latitude,
                    "Longitude": longitude,
                    "ISP": isp
                },
                "Status Code": response.status,
                "WAF Detection Result": [waf],
                "Server": server_info,
                "Protection Methods": "Rate Limiting, Captcha" if waf != "Unknown" else "None"
            }
            return data
    except Exception as e:
        return {"Target URL": url, "Error": str(e)}

async def save_results(domain, data):
    directory = extract_domain(domain)
    print(directory)
    os.makedirs(directory, exist_ok=True)

    filename = os.path.join(directory, f"{directory}_WAF_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

    try:
        with open(filename, "w") as file:
            json.dump(data, file, indent=4)
        console.print(f"[bold green]✅ Results saved in {filename}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]❌ Error saving data: {e}[/bold red]")

async def create_maps(results):
    for result in results:
        latitude = result.get("IP Information", {}).get("Latitude")
        longitude = result.get("IP Information", {}).get("Longitude")
        if latitude and longitude:
            target_url = result["Target URL"].replace("https://", "").replace("http://", "").replace("/", "_")
            waf_map = folium.Map(location=[latitude, longitude], zoom_start=6)

            folium.Marker(
                [latitude, longitude],
                popup=f"<b>{result['Target URL']}</b><br>WAF: {result['WAF Detection Result'][0]}<br>Location: {result['IP Information']['Location']}<br>ISP: {result['IP Information']['ISP']}",
                icon=folium.Icon(color='blue', icon='info-sign')
            ).add_to(waf_map)

            map_file = f"data/{target_url}_map.html"
            waf_map.save(map_file)
            console.print(f"[bold green]🌍 Map generated: {map_file}[/bold green]")

async def WafScanner(target):
    target_input = target #input("Enter a single URL/IP or path to a .txt file containing multiple targets: ").strip()

    if os.path.isfile(target_input):
        with open(target_input, "r") as file:
            targets = [line.strip() for line in file.readlines() if line.strip()]
    else:
        targets = [target_input]

    if not targets:
        console.print("[bold red]❌ No valid targets provided. Exiting...[/bold red]")
        return

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("{task.completed}/{task.total} targets scanned")) as progress:
        task = progress.add_task("[cyan]Scanning Targets...[/cyan]", total=len(targets))
        async with aiohttp.ClientSession() as session:
            results = await asyncio.gather(*(scan_target(session, target) for target in targets))
            progress.update(task, advance=len(targets))

    table = Table(title="🚨 Advanced WAF Detection Tool Results 🚨")
    for column in ["Target URL", "IP Address", "Location", "Status Code", "WAF Detected", "Server", "Protection Methods"]:
        table.add_column(column, style="cyan", overflow="fold")

    for result in results:
        table.add_row(
            result.get("Target URL", "N/A"),
            result.get("IP Information", {}).get("IP Address", "N/A"),
            result.get("IP Information", {}).get("Location", "N/A"),
            str(result.get("Status Code", "N/A")),
            ", ".join(result.get("WAF Detection Result", ["N/A"])),
            result.get("Server", "Unknown Server"),
            result.get("Protection Methods", "N/A")
        )

    console.print(table)

    await save_results(target, results)
    # await create_maps(results)

def Waf(target):
    asyncio.run(WafScanner(target))

# Waf('https://pixiv.net')