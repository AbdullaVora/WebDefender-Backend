# import requests
# import json
# import socket
# import asyncio
# import aiohttp
# import re
# import time
# import folium
# from geopy.geocoders import Nominatim
# from rich.console import Console
# from rich.table import Table
# from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
# from urllib.parse import urlparse
# import os

# console = Console()

# WAF_SIGNATURES = {
#     "Cloudflare": [r'cloudflare', r'__cfduid'],
#     "AWS Shield": [r'aws-shield'],
#     "Imperva": [r'imperva'],
#     "F5 Big-IP": [r'big-ip'],
#     "Barracuda": [r'barracuda'],
#     "Sucuri": [r'sucuri'],
#     "Palo Alto": [r'paloalto'],
#     "Akamai": [r'akamai'],
#     "Fortinet": [r'fortinet'],
#     "Citrix": [r'citrix'],
#     "DenyAll": [r'denyall'],
#     "NetScaler": [r'netscaler'],
#     "ModSecurity": [r'modsecurity'],
#     "StackPath": [r'stackpath'],
#     "Incapsula": [r'incapsula'],
#     "Reblaze": [r'reblaze'],
#     "Wallarm": [r'wallarm'],
#     "Ergon": [r'ergon'],
#     "PowerCDN": [r'powercdn'],
#     "DDoS-Guard": [r'ddos-guard'],
#     "ArvanCloud": [r'arvancloud'],
#     "BitNinja": [r'bitninja'],
#     "Varnish": [r'varnish'],
#     "Grey Wizard": [r'grey wizard'],
# }

# SERVER_SIGNATURES = {
#     "Apache": [r'apache'],
#     "Nginx": [r'nginx'],
#     "IIS": [r'microsoft-iis'],
#     "LiteSpeed": [r'litespeed'],
#     "Caddy": [r'caddy'],
#     "Tomcat": [r'tomcat'],
#     "Gunicorn": [r'gunicorn'],
#     "OpenResty": [r'openresty'],
#     "Jetty": [r'jetty'],
#     "Express": [r'express'],
#     "Node.js": [r'node\.js'],
#     "Envoy": [r'envoy'],
#     "Cherokee": [r'cherokee'],
#     "Lighttpd": [r'lighttpd'],
#     "Træfik": [r'traefik'],
#     "IBM WebSphere": [r'websphere'],
#     "Oracle WebLogic": [r'weblogic'],
#     "Resin": [r'resin'],
#     "Zeus": [r'zeus'],
#     "Roxen": [r'roxen'],
# }

# os.makedirs("data", exist_ok=True)

# async def get_ip(domain):
#     ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
#     if ip_pattern.match(domain):
#         return domain

#     try:
#         return socket.gethostbyname(domain)
#     except socket.gaierror:
#         return "Unknown IP"

# async def get_geo_info(ip):
#     try:
#         async with aiohttp.ClientSession() as session:
#             async with session.get(f"https://ipinfo.io/{ip}/json", timeout=10) as response:
#                 data = await response.json()
#                 city = data.get("city", "Unknown City")
#                 region = data.get("region", "Unknown Region")
#                 isp = data.get("org", "Unknown ISP")

#                 geolocator = Nominatim(user_agent="geoapi")
#                 location = geolocator.geocode(f"{city}, {region}")
#                 latitude, longitude = (location.latitude, location.longitude) if location else (None, None)

#                 return city, region, isp, latitude, longitude
#     except Exception:
#         return "Unknown City", "Unknown Region", "Unknown ISP", None, None

# def detect_waf(headers):
#     for waf, patterns in WAF_SIGNATURES.items():
#         if any(re.search(pattern, str(value), re.IGNORECASE) for pattern in patterns for value in headers.values()):
#             return waf
#     return "Unknown"

# def detect_server(headers):
#     for server, patterns in SERVER_SIGNATURES.items():
#         if any(re.search(pattern, str(value), re.IGNORECASE) for pattern in patterns for value in headers.values()):
#             return server
#     return "Unknown Server"

# async def scan_target(session, url):
#     parsed_url = urlparse(url).netloc or url
#     ip_address = await get_ip(parsed_url)
#     if ip_address == "Unknown IP":
#         return {"Target URL": url, "Error": "Invalid domain or IP address"}

#     if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip_address):
#         url = f"http://{ip_address}"

#     try:
#         async with session.get(url, timeout=10) as response:
#             waf = detect_waf(response.headers)
#             server_info = detect_server(response.headers)
#             city, region, isp, latitude, longitude = await get_geo_info(ip_address)

#             data = {
#                 "Target URL": parsed_url,
#                 "IP Information": {
#                     "IP Address": ip_address,
#                     "Location": f"{city}, {region}",
#                     "Latitude": latitude,
#                     "Longitude": longitude,
#                     "ISP": isp
#                 },
#                 "Status Code": response.status,
#                 "WAF Detection Result": [waf],
#                 "Server": server_info,
#                 "Protection Methods": "Rate Limiting, Captcha" if waf != "Unknown" else "None"
#             }
#             return data
#     except Exception as e:
#         return {"Target URL": url, "Error": str(e)}

# async def save_results(data, output_file="data/scan_results.json"):
#     try:
#         with open(output_file, "w") as file:
#             json.dump(data, file, indent=4)
#         console.print(f"[bold green]✅ Results saved in {output_file}[/bold green]")
#     except Exception as e:
#         console.print(f"[bold red]❌ Error saving data: {e}[/bold red]")

# async def create_maps(results):
#     for result in results:
#         latitude = result.get("IP Information", {}).get("Latitude")
#         longitude = result.get("IP Information", {}).get("Longitude")
#         if latitude and longitude:
#             target_url = result["Target URL"].replace("https://", "").replace("http://", "").replace("/", "_")
#             waf_map = folium.Map(location=[latitude, longitude], zoom_start=6)

#             folium.Marker(
#                 [latitude, longitude],
#                 popup=f"<b>{result['Target URL']}</b><br>WAF: {result['WAF Detection Result'][0]}<br>Location: {result['IP Information']['Location']}<br>ISP: {result['IP Information']['ISP']}",
#                 icon=folium.Icon(color='blue', icon='info-sign')
#             ).add_to(waf_map)

#             map_file = f"data/{target_url}_map.html"
#             waf_map.save(map_file)
#             console.print(f"[bold green]🌍 Map generated: {map_file}[/bold green]")

# async def main():
#     console.print("[bold cyan]🌍 Welcome to the [green]Advanced WAF Detection Tool![/green] 🌍")
#     target_input = input("Enter a single URL/IP or path to a .txt file containing multiple targets: ").strip()

#     if os.path.isfile(target_input):
#         with open(target_input, "r") as file:
#             targets = [line.strip() for line in file.readlines() if line.strip()]
#     else:
#         targets = [target_input]

#     if not targets:
#         console.print("[bold red]❌ No valid targets provided. Exiting...[/bold red]")
#         return

#     with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("{task.completed}/{task.total} targets scanned")) as progress:
#         task = progress.add_task("[cyan]Scanning Targets...[/cyan]", total=len(targets))
#         async with aiohttp.ClientSession() as session:
#             results = await asyncio.gather(*(scan_target(session, target) for target in targets))
#             progress.update(task, advance=len(targets))

#     table = Table(title="🚨 Advanced WAF Detection Tool Results 🚨")
#     for column in ["Target URL", "IP Address", "Location", "Status Code", "WAF Detected", "Server", "Protection Methods"]:
#         table.add_column(column, style="cyan", overflow="fold")

#     for result in results:
#         table.add_row(
#             result.get("Target URL", "N/A"),
#             result.get("IP Information", {}).get("IP Address", "N/A"),
#             result.get("IP Information", {}).get("Location", "N/A"),
#             str(result.get("Status Code", "N/A")),
#             ", ".join(result.get("WAF Detection Result", ["N/A"])),
#             result.get("Server", "Unknown Server"),
#             result.get("Protection Methods", "N/A")
#         )

#     console.print(table)

#     await save_results(results)
#     await create_maps(results)

# if __name__ == "__main__":
#     asyncio.run(main())



# import asyncio
# import json
# import socket
# import re
# import aiohttp
# import folium
# from geopy.geocoders import Nominatim
# from urllib.parse import urlparse
# import os

# # Copy WAF_SIGNATURES and SERVER_SIGNATURES from your original code
# WAF_SIGNATURES = {
#     "Cloudflare": [r'cloudflare', r'__cfduid'],
#     "AWS Shield": [r'aws-shield'],
#     # ... rest of your signatures
# }

# SERVER_SIGNATURES = {
#     "Apache": [r'apache'],
#     "Nginx": [r'nginx'],
#     # ... rest of your signatures
# }

# os.makedirs("data", exist_ok=True)

# async def get_ip(domain):
#     ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
#     if ip_pattern.match(domain):
#         return domain

#     try:
#         return socket.gethostbyname(domain)
#     except socket.gaierror:
#         return "Unknown IP"

# async def get_geo_info(ip):
#     try:
#         async with aiohttp.ClientSession() as session:
#             async with session.get(f"https://ipinfo.io/{ip}/json", timeout=10) as response:
#                 data = await response.json()
#                 city = data.get("city", "Unknown City")
#                 region = data.get("region", "Unknown Region")
#                 isp = data.get("org", "Unknown ISP")

#                 geolocator = Nominatim(user_agent="geoapi")
#                 location = geolocator.geocode(f"{city}, {region}")
#                 latitude, longitude = (location.latitude, location.longitude) if location else (None, None)

#                 return city, region, isp, latitude, longitude
#     except Exception:
#         return "Unknown City", "Unknown Region", "Unknown ISP", None, None

# def detect_waf(headers):
#     for waf, patterns in WAF_SIGNATURES.items():
#         if any(re.search(pattern, str(value), re.IGNORECASE) for pattern in patterns for value in headers.values()):
#             return waf
#     return "Unknown"

# def detect_server(headers):
#     for server, patterns in SERVER_SIGNATURES.items():
#         if any(re.search(pattern, str(value), re.IGNORECASE) for pattern in patterns for value in headers.values()):
#             return server
#     return "Unknown Server"

# async def scan_target(url):
#     parsed_url = urlparse(url).netloc or url
#     ip_address = await get_ip(parsed_url)
#     if ip_address == "Unknown IP":
#         return {"Target URL": url, "Error": "Invalid domain or IP address"}

#     if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip_address):
#         url = f"http://{ip_address}"

#     try:
#         async with aiohttp.ClientSession() as session:
#             async with session.get(url, timeout=10) as response:
#                 waf = detect_waf(response.headers)
#                 server_info = detect_server(response.headers)
#                 city, region, isp, latitude, longitude = await get_geo_info(ip_address)

#                 data = {
#                     "scanType": "WAFDetector",
#                     "Target URL": parsed_url,
#                     "IP Information": {
#                         "IP Address": ip_address,
#                         "Location": f"{city}, {region}",
#                         "Latitude": latitude,
#                         "Longitude": longitude,
#                         "ISP": isp
#                     },
#                     "Status Code": response.status,
#                     "WAF Detection Result": [waf],
#                     "Server": server_info,
#                     "Protection Methods": "Rate Limiting, Captcha" if waf != "Unknown" else "None"
#                 }
#                 return data
#     except Exception as e:
#         return {"Target URL": url, "Error": str(e)}

# async def create_map(result):
#     latitude = result.get("IP Information", {}).get("Latitude")
#     longitude = result.get("IP Information", {}).get("Longitude")
#     if latitude and longitude:
#         target_url = result["Target URL"].replace("https://", "").replace("http://", "").replace("/", "_")
#         waf_map = folium.Map(location=[latitude, longitude], zoom_start=6)

#         folium.Marker(
#             [latitude, longitude],
#             popup=f"<b>{result['Target URL']}</b><br>WAF: {result['WAF Detection Result'][0]}<br>Location: {result['IP Information']['Location']}<br>ISP: {result['IP Information']['ISP']}",
#             icon=folium.Icon(color='blue', icon='info-sign')
#         ).add_to(waf_map)

#         map_file = f"data/{target_url}_map.html"
#         waf_map.save(map_file)
#         return map_file
#     return None

import asyncio
import json
import socket
import re
import aiohttp
import folium
from geopy.geocoders import Nominatim
from urllib.parse import urlparse
import os
import logging

os.makedirs("data", exist_ok=True)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("data/waf_scan.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("WAFDetector")

# Copy WAF_SIGNATURES and SERVER_SIGNATURES from your original code
WAF_SIGNATURES = {
    "Cloudflare": [r'cloudflare', r'__cfduid'],
    "AWS Shield": [r'aws-shield'],
    # ... rest of your signatures
}

SERVER_SIGNATURES = {
    "Apache": [r'apache'],
    "Nginx": [r'nginx'],
    # ... rest of your signatures
}

# Create data directory if it doesn't exist
os.makedirs("data", exist_ok=True)

async def get_ip(domain):
    ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    if ip_pattern.match(domain):
        logger.info(f"Input is already an IP address: {domain}")
        return domain

    try:
        ip = socket.gethostbyname(domain)
        logger.info(f"Resolved domain {domain} to IP {ip}")
        return ip
    except socket.gaierror as e:
        logger.error(f"Failed to resolve domain {domain}: {str(e)}")
        return "Unknown IP"

async def get_geo_info(ip):
    try:
        logger.info(f"Getting geo information for IP: {ip}")
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://ipinfo.io/{ip}/json", timeout=10) as response:
                data = await response.json()
                city = data.get("city", "Unknown City")
                region = data.get("region", "Unknown Region")
                isp = data.get("org", "Unknown ISP")
                
                logger.info(f"IP info retrieved: {city}, {region}, {isp}")

                geolocator = Nominatim(user_agent="geoapi")
                location = geolocator.geocode(f"{city}, {region}")
                latitude, longitude = (location.latitude, location.longitude) if location else (None, None)
                
                if latitude and longitude:
                    logger.info(f"Geocoded location: {latitude}, {longitude}")
                else:
                    logger.warning(f"Could not geocode location for {city}, {region}")

                return city, region, isp, latitude, longitude
    except Exception as e:
        logger.error(f"Error getting geo information for {ip}: {str(e)}")
        return "Unknown City", "Unknown Region", "Unknown ISP", None, None

def detect_waf(headers):
    detected_wafs = []
    for waf, patterns in WAF_SIGNATURES.items():
        if any(re.search(pattern, str(value), re.IGNORECASE) for pattern in patterns for value in headers.values()):
            detected_wafs.append(waf)
            logger.info(f"Detected WAF: {waf}")
    
    if not detected_wafs:
        logger.info("No WAF detected")
        return "Unknown"
    return detected_wafs

def detect_server(headers):
    for server, patterns in SERVER_SIGNATURES.items():
        if any(re.search(pattern, str(value), re.IGNORECASE) for pattern in patterns for value in headers.values()):
            logger.info(f"Detected server: {server}")
            return server
    
    logger.info("Could not identify server type")
    return "Unknown Server"

async def scan_target(url):
    logger.info(f"Starting scan for target: {url}")
    parsed_url = urlparse(url).netloc or url
    ip_address = await get_ip(parsed_url)
    
    if ip_address == "Unknown IP":
        logger.error(f"Invalid domain or IP address: {parsed_url}")
        return {"Target URL": url, "Error": "Invalid domain or IP address"}

    if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip_address):
        url = f"http://{ip_address}"
        logger.info(f"Using IP directly as URL: {url}")

    try:
        async with aiohttp.ClientSession() as session:
            logger.info(f"Sending request to {url}")
            async with session.get(url, timeout=10) as response:
                status_code = response.status
                logger.info(f"Received response with status code: {status_code}")
                
                headers_log = {k: v for k, v in response.headers.items()}
                logger.info(f"Response headers: {json.dumps(headers_log)}")
                
                waf_result = detect_waf(response.headers)
                server_info = detect_server(response.headers)
                city, region, isp, latitude, longitude = await get_geo_info(ip_address)

                # Read scan logs
                with open("data/waf_scan.log", "r") as log_file:
                    scan_logs = log_file.readlines()
                
                # Get only recent logs relevant to this scan
                relevant_logs = [log for log in scan_logs if parsed_url in log][-10:]  # Last 10 relevant log entries

                data = {
                    "scanType": "WAFDetector",
                    "Target_URL": parsed_url,
                    "IP_Information": {
                        "IPAddress": ip_address,
                        "Location": f"{city}, {region}",
                        "Latitude": latitude,
                        "Longitude": longitude,
                        "ISP": isp
                    },
                    "Status_Code": status_code,
                    "WAF_Detection_Result": waf_result if isinstance(waf_result, list) else [waf_result],
                    "Server": server_info,
                    "Protection_Methods": "Rate Limiting, Captcha" if waf_result != "Unknown" else "None",
                    "logs": relevant_logs
                }
                
                # Save result to JSON file
                target_name = parsed_url.replace(".", "_")
                result_file = f"data/{target_name}_result.json"
                with open(result_file, "w") as f:
                    json.dump(data, f, indent=4)
                
                logger.info(f"Scan completed for {parsed_url}. Results saved to {result_file}")
                return data
                
    except Exception as e:
        error_msg = f"Error scanning {url}: {str(e)}"
        logger.error(error_msg)
        return {"Target URL": url, "Error": error_msg, "Scan Logs": get_recent_logs()}

def get_recent_logs(num_lines=20):
    """Get the most recent log entries"""
    try:
        with open("data/waf_scan.log", "r") as log_file:
            logs = log_file.readlines()
            return logs[-num_lines:]  # Return last n lines
    except Exception as e:
        return [f"Error reading logs: {str(e)}"]

async def create_map(result):
    try:
        latitude = result.get("IP Information", {}).get("Latitude")
        longitude = result.get("IP Information", {}).get("Longitude")
        
        if latitude and longitude:
            logger.info(f"Creating map for coordinates: {latitude}, {longitude}")
            target_url = result["Target URL"].replace("https://", "").replace("http://", "").replace("/", "_")
            waf_map = folium.Map(location=[latitude, longitude], zoom_start=6)

            # Format WAF info for popup
            waf_info = ", ".join(result['WAF Detection Result']) if isinstance(result['WAF Detection Result'], list) else result['WAF Detection Result']
            
            folium.Marker(
                [latitude, longitude],
                popup=f"<b>{result['Target URL']}</b><br>WAF: {waf_info}<br>Location: {result['IP Information']['Location']}<br>ISP: {result['IP Information']['ISP']}",
                icon=folium.Icon(color='blue', icon='info-sign')
            ).add_to(waf_map)

            map_file = f"data/{target_url}_map.html"
            waf_map.save(map_file)
            logger.info(f"Map saved to {map_file}")
            return map_file
        else:
            logger.warning("No coordinates available for map creation")
            return None
    except Exception as e:
        logger.error(f"Error creating map: {str(e)}")
        return None

async def main():
    """Example usage of the scanner"""
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "example.com"  # Default target
    
    logger.info(f"Starting WAF detection for {target}")
    result = await scan_target(target)
    
    if "Error" not in result:
        map_file = await create_map(result)
        if map_file:
            logger.info(f"Map created at {map_file}")
    
    # Output results to console
    print(json.dumps(result, indent=4))
    logger.info("Scan completed")

if __name__ == "__main__":
    asyncio.run(main())