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
from datetime import datetime

os.makedirs("data", exist_ok=True)

# Set up comprehensive logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("data/waf_scan.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("WAFDetector")

# Performance logging setup
perf_logger = logging.getLogger("PerformanceLogger")
perf_logger.setLevel(logging.INFO)
perf_handler = logging.FileHandler("data/performance.log")
perf_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
perf_logger.addHandler(perf_handler)

# Copy WAF_SIGNATURES and SERVER_SIGNATURES from your original code
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
    # ... rest of your signatures
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
    # ... rest of your signatures
}


class ScanLogger:
    """Helper class to log scan activities"""
    def __init__(self, target):
        self.target = target
        self.scan_id = datetime.now().strftime("%Y%m%d%H%M%S")
        self.log_file = f"data/scan_{self.scan_id}.log"
        self.activity_log = []
        
        # Setup scan-specific logger
        self.scan_logger = logging.getLogger(f"ScanLogger-{self.scan_id}")
        self.scan_logger.setLevel(logging.INFO)
        handler = logging.FileHandler(self.log_file)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
        self.scan_logger.addHandler(handler)
        
    def log_activity(self, message):
        """Log an activity message"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.activity_log.append(log_entry)
        self.scan_logger.info(message)
        logger.info(f"{self.target}: {message}")
        
    def log_performance(self, operation, duration):
        """Log performance metrics"""
        perf_logger.info(f"{self.scan_id} - {self.target} - {operation} took {duration:.2f} seconds")
        
    def get_logs(self):
        """Get all logs for this scan"""
        return self.activity_log
WAF_DESCRIPTION_DATASET = {
    "Cloudflare": {
        "class": "Cloudflare WAF",
        "description": "Cloudflare provides DDoS protection and WAF services by inspecting and filtering HTTP/S traffic before reaching the origin server.",
        "severity": "info"
    },
    "AWS Shield": {
        "class": "AWS Shield WAF",
        "description": "AWS Shield protects applications running on AWS against DDoS attacks with automatic traffic analysis and mitigation.",
        "severity": "info"
    },
    "Imperva": {
        "class": "Imperva WAF",
        "description": "Imperva defends websites and APIs against a broad range of attacks including DDoS, SQL injection, and XSS.",
        "severity": "info"
    },
    "F5 Big-IP": {
        "class": "F5 BIG-IP WAF",
        "description": "BIG-IP Application Security Manager (ASM) from F5 offers advanced web application firewall capabilities.",
        "severity": "info"
    },
    "Barracuda": {
        "class": "Barracuda WAF",
        "description": "Barracuda offers protection against OWASP Top 10 threats, DDoS, and provides traffic load balancing.",
        "severity": "info"
    },
    "Sucuri": {
        "class": "Sucuri WAF",
        "description": "Sucuri firewall protects websites from DDoS, malware, and hackers, focusing heavily on small-to-medium businesses.",
        "severity": "info"
    },
    "Palo Alto": {
        "class": "Palo Alto Networks WAF",
        "description": "Palo Alto firewalls include security features like advanced threat prevention, URL filtering, and DDoS mitigation.",
        "severity": "info"
    },
    "Akamai": {
        "class": "Akamai Kona Site Defender",
        "description": "Akamai provides edge-based security protection, WAF services, and global CDN acceleration.",
        "severity": "info"
    },
    "Fortinet": {
        "class": "Fortinet FortiWeb",
        "description": "Fortinet offers FortiWeb, a web application firewall protecting applications and APIs from attacks and vulnerabilities.",
        "severity": "info"
    },
    "Citrix": {
        "class": "Citrix WAF",
        "description": "Citrix Application Firewall helps protect web applications against OWASP Top 10 vulnerabilities and zero-day threats.",
        "severity": "info"
    },
    "DenyAll": {
        "class": "DenyAll WAF",
        "description": "DenyAll provides security against application-layer attacks, focusing on customizable security policies.",
        "severity": "info"
    },
    "NetScaler": {
        "class": "NetScaler AppFirewall",
        "description": "NetScaler (now Citrix ADC) offers WAF features along with traffic optimization and load balancing.",
        "severity": "info"
    },
    "ModSecurity": {
        "class": "ModSecurity WAF",
        "description": "ModSecurity is an open-source WAF engine capable of real-time web application monitoring, logging, and access control.",
        "severity": "info"
    },
    "StackPath": {
        "class": "StackPath WAF",
        "description": "StackPath provides WAF services integrated into its secure edge computing and CDN platform.",
        "severity": "info"
    },
    "Incapsula": {
        "class": "Imperva Incapsula WAF",
        "description": "Incapsula (now part of Imperva) offers DDoS protection and intelligent WAF features for businesses.",
        "severity": "info"
    },
    "Reblaze": {
        "class": "Reblaze WAF",
        "description": "Reblaze offers a fully managed, cloud-based web security platform featuring WAF, bot management, and DDoS protection.",
        "severity": "info"
    },
    "Wallarm": {
        "class": "Wallarm WAF",
        "description": "Wallarm uses machine learning to protect APIs and web apps against both known and unknown attacks.",
        "severity": "info"
    },
    "Ergon": {
        "class": "Ergon Airlock WAF",
        "description": "Ergon Airlock offers integrated WAF and secure access management for web applications and APIs.",
        "severity": "info"
    },
    "PowerCDN": {
        "class": "PowerCDN WAF",
        "description": "PowerCDN delivers DDoS protection and WAF capabilities through its global content delivery network infrastructure.",
        "severity": "info"
    },
    "DDoS-Guard": {
        "class": "DDoS-Guard WAF",
        "description": "DDoS-Guard provides protection against volumetric DDoS attacks and web application vulnerabilities.",
        "severity": "info"
    },
    "ArvanCloud": {
        "class": "ArvanCloud WAF",
        "description": "ArvanCloud offers WAF features combined with CDN, cloud security, and optimization services.",
        "severity": "info"
    },
    "BitNinja": {
        "class": "BitNinja WAF",
        "description": "BitNinja focuses on server security combining WAF, DDoS mitigation, and malware detection.",
        "severity": "info"
    },
    "Varnish": {
        "class": "Varnish Web Accelerator",
        "description": "Varnish is primarily a caching HTTP reverse proxy; it can help with DDoS mitigation but is not a WAF by design.",
        "severity": "info"
    },
    "Grey Wizard": {
        "class": "Grey Wizard WAF",
        "description": "Grey Wizard provides cloud WAF, DDoS protection, and bot mitigation targeted at web platforms.",
        "severity": "info"
    }
}


SERVER_DESCRIPTION_DATASET = {
    "Apache": {
        "class": "Apache HTTP Server",
        "description": "The most widely used open-source web server, known for flexibility, power, and rich module ecosystem.",
        "severity": "info"
    },
    "Nginx": {
        "class": "Nginx Web Server",
        "description": "A popular web server and reverse proxy known for high performance, stability, and low resource usage.",
        "severity": "info"
    },
    "IIS": {
        "class": "Microsoft IIS",
        "description": "Internet Information Services is Microsoft's web server designed for Windows Server platforms.",
        "severity": "info"
    },
    "LiteSpeed": {
        "class": "LiteSpeed Web Server",
        "description": "A high-performance, commercial web server known for efficient PHP handling and DDoS protection.",
        "severity": "info"
    },
    "Caddy": {
        "class": "Caddy Web Server",
        "description": "Caddy is a modern web server with automatic HTTPS and easy configuration built-in.",
        "severity": "info"
    },
    "Tomcat": {
        "class": "Apache Tomcat",
        "description": "An open-source Java Servlet Container developed by the Apache Software Foundation.",
        "severity": "info"
    },
    "Gunicorn": {
        "class": "Gunicorn Server",
        "description": "Python WSGI HTTP server for UNIX designed for running web applications in production environments.",
        "severity": "info"
    },
    "OpenResty": {
        "class": "OpenResty",
        "description": "A web platform based on Nginx and LuaJIT designed to build scalable web apps, web services, and dynamic APIs.",
        "severity": "info"
    },
    "Jetty": {
        "class": "Eclipse Jetty",
        "description": "A lightweight Java web server and servlet container often used for machine-to-machine communication.",
        "severity": "info"
    },
    "Express": {
        "class": "Express.js",
        "description": "Minimalist web framework for Node.js, used to build APIs and web apps quickly and efficiently.",
        "severity": "info"
    },
    "Node.js": {
        "class": "Node.js HTTP Server",
        "description": "Node.js can serve HTTP content directly using its built-in server modules without a third-party server.",
        "severity": "info"
    },
    "Envoy": {
        "class": "Envoy Proxy",
        "description": "High-performance open-source edge and service proxy designed for cloud-native applications.",
        "severity": "info"
    },
    "Cherokee": {
        "class": "Cherokee Web Server",
        "description": "User-friendly, high-performance, flexible web server for UNIX-like operating systems.",
        "severity": "info"
    },
    "Lighttpd": {
        "class": "Lighttpd",
        "description": "Lightweight web server optimized for high-performance environments and low memory footprint.",
        "severity": "info"
    },
    "Træfik": {
        "class": "Traefik Proxy",
        "description": "A modern HTTP reverse proxy and load balancer for microservices architecture.",
        "severity": "info"
    },
    "IBM WebSphere": {
        "class": "IBM WebSphere",
        "description": "IBM's robust application server designed for enterprise-level Java applications and web services.",
        "severity": "info"
    },
    "Oracle WebLogic": {
        "class": "Oracle WebLogic Server",
        "description": "Enterprise-level Java EE application server by Oracle for deploying distributed applications and services.",
        "severity": "info"
    },
    "Resin": {
        "class": "Caucho Resin Server",
        "description": "Web server and Java EE application server optimized for high-performance, reliability, and scalability.",
        "severity": "info"
    },
    "Zeus": {
        "class": "Zeus Web Server",
        "description": "Commercial web server solution designed for performance and scalability, now largely discontinued.",
        "severity": "info"
    },
    "Roxen": {
        "class": "Roxen Web Server",
        "description": "Flexible, scriptable web server focused on modular design and embedded scripting.",
        "severity": "info"
    }
}


# Create data directory if it doesn't exist
os.makedirs("data", exist_ok=True)

async def get_ip(domain, scan_logger):
    start_time = datetime.now()
    ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    
    if ip_pattern.match(domain):
        scan_logger.log_activity(f"Input is already an IP address: {domain}")
        duration = (datetime.now() - start_time).total_seconds()
        scan_logger.log_performance("IP resolution", duration)
        return domain

    try:
        scan_logger.log_activity(f"Resolving domain: {domain}")
        ip = socket.gethostbyname(domain)
        scan_logger.log_activity(f"Resolved domain {domain} to IP {ip}")
        duration = (datetime.now() - start_time).total_seconds()
        scan_logger.log_performance("IP resolution", duration)
        return ip
    except socket.gaierror as e:
        scan_logger.log_activity(f"Failed to resolve domain {domain}: {str(e)}")
        duration = (datetime.now() - start_time).total_seconds()
        scan_logger.log_performance("IP resolution", duration)
        return "Unknown IP"

async def get_geo_info(ip, scan_logger):
    start_time = datetime.now()
    try:
        scan_logger.log_activity(f"Getting geo information for IP: {ip}")
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://ipinfo.io/{ip}/json", timeout=10) as response:
                data = await response.json()
                city = data.get("city", "Unknown City")
                region = data.get("region", "Unknown Region")
                isp = data.get("org", "Unknown ISP")
                
                scan_logger.log_activity(f"IP info retrieved: {city}, {region}, {isp}")

                geolocator = Nominatim(user_agent="geoapi")
                location = geolocator.geocode(f"{city}, {region}")
                latitude, longitude = (location.latitude, location.longitude) if location else (None, None)
                
                if latitude and longitude:
                    scan_logger.log_activity(f"Geocoded location: {latitude}, {longitude}")
                else:
                    scan_logger.log_activity(f"Could not geocode location for {city}, {region}")

                duration = (datetime.now() - start_time).total_seconds()
                scan_logger.log_performance("Geo info lookup", duration)
                return city, region, isp, latitude, longitude
    except Exception as e:
        scan_logger.log_activity(f"Error getting geo information for {ip}: {str(e)}")
        duration = (datetime.now() - start_time).total_seconds()
        scan_logger.log_performance("Geo info lookup", duration)
        return "Unknown City", "Unknown Region", "Unknown ISP", None, None

def detect_waf(headers, scan_logger):
    start_time = datetime.now()
    detected_wafs = []
    for waf, patterns in WAF_SIGNATURES.items():
        if any(re.search(pattern, str(value), re.IGNORECASE) for pattern in patterns for value in headers.values()):
            detected_wafs.append(waf)
            scan_logger.log_activity(f"Detected WAF: {waf}")
    
    if not detected_wafs:
        scan_logger.log_activity("No WAF detected")
    
    duration = (datetime.now() - start_time).total_seconds()
    scan_logger.log_performance("WAF detection", duration)
    
    return detected_wafs if detected_wafs else ["Unknown"]

def detect_server(headers, scan_logger):
    start_time = datetime.now()
    for server, patterns in SERVER_SIGNATURES.items():
        if any(re.search(pattern, str(value), re.IGNORECASE) for pattern in patterns for value in headers.values()):
            scan_logger.log_activity(f"Detected server: {server}")
            duration = (datetime.now() - start_time).total_seconds()
            scan_logger.log_performance("Server detection", duration)
            return server
    
    scan_logger.log_activity("Could not identify server type")
    duration = (datetime.now() - start_time).total_seconds()
    scan_logger.log_performance("Server detection", duration)
    return "Unknown Server"

async def scan_target(url):
    scan_logger = ScanLogger(url)
    scan_logger.log_activity(f"Starting scan for target: {url}")
    
    parsed_url = urlparse(url).netloc or url
    ip_address = await get_ip(parsed_url, scan_logger)
    
    if ip_address == "Unknown IP":
        scan_logger.log_activity(f"Invalid domain or IP address: {parsed_url}")
        return {"Target URL": url, "Error": "Invalid domain or IP address", "logs": scan_logger.get_logs()}

    if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip_address):
        url = f"http://{ip_address}"
        scan_logger.log_activity(f"Using IP directly as URL: {url}")

    try:
        scan_start = datetime.now()
        async with aiohttp.ClientSession() as session:
            scan_logger.log_activity(f"Sending request to {url}")
            request_start = datetime.now()
            async with session.get(url, timeout=10) as response:
                request_duration = (datetime.now() - request_start).total_seconds()
                scan_logger.log_performance("HTTP request", request_duration)
                
                status_code = response.status
                scan_logger.log_activity(f"Received response with status code: {status_code}")
                
                headers_log = {k: v for k, v in response.headers.items()}
                scan_logger.log_activity(f"Response headers: {json.dumps(headers_log)}")
                
                waf_result = detect_waf(response.headers, scan_logger)
                server_info = detect_server(response.headers, scan_logger)
                city, region, isp, latitude, longitude = await get_geo_info(ip_address, scan_logger)
                # Get all scan logs
                scan_logs = scan_logger.get_logs()
                # WAF Description handling
                if isinstance(waf_result, list) and waf_result and waf_result[0] in WAF_DESCRIPTION_DATASET:
                    waf_description_info = WAF_DESCRIPTION_DATASET[waf_result[0]]
                else:
                    waf_description_info = {
                        "class": "Unknown WAF",
                        "description": "No known WAF detected or matched.",
                        "severity": "info"
                    }

                # Server Description handling
                if server_info in SERVER_DESCRIPTION_DATASET:
                    server_description_info = SERVER_DESCRIPTION_DATASET[server_info]
                else:
                    server_description_info = {
                        "class": "Unknown Server",
                        "description": "No known server technology detected.",
                        "severity": "info"
                    }




                # Read scan logs
                with open("data/waf_scan.log", "r") as log_file:
                    scan_logs = log_file.readlines()
                    scan_duration = (datetime.now() - scan_start).total_seconds()
                    scan_logger.log_performance("Total scan", scan_duration)

                data = {
                    "scanType": "WAFDetector",
                    "scanId": scan_logger.scan_id,
                    "Target_URL": parsed_url,
                    "IP_Information": {
                        "IPAddress": ip_address,
                        "Location": f"{city}, {region}",
                        "Latitude": latitude,
                        "Longitude": longitude,
                        "ISP": isp
                    },
                    "Status_Code": status_code,
                    "WAF_Detection_Result": waf_result,
                    "Server": server_info,
                    "Protection_Methods": "Rate Limiting, Captcha" if waf_result != ["Unknown"] else "None",
                    "PerformanceMetrics": {
                        "TotalScanTime": scan_duration,
                        "HTTPRequestTime": request_duration
                    },
                    "logs": scan_logs,
                    "WAF_Detection_Result": waf_result if isinstance(waf_result, list) else [waf_result],
                    "WAF_Info": waf_description_info,
                    "Server": server_info,
                    "Server_Info": server_description_info,
                    "Protection_Methods": "Rate Limiting, Captcha" if waf_result != "Unknown" else "None",
                    "logs": scan_logs
                }

                
                # Save result to JSON file
                target_name = parsed_url.replace(".", "_")
                result_file = f"data/{target_name}_{scan_logger.scan_id}_result.json"
                with open(result_file, "w") as f:
                    json.dump(data, f, indent=4)
                
                scan_logger.log_activity(f"Scan completed for {parsed_url}. Results saved to {result_file}")
                return data
                
    except Exception as e:
        error_msg = f"Error scanning {url}: {str(e)}"
        scan_logger.log_activity(error_msg)
        return {
            "Target URL": url, 
            "Error": error_msg, 
            "logs": scan_logger.get_logs(),
            "scanId": scan_logger.scan_id
        }

async def create_map(result):
    try:
        scan_logger = ScanLogger(result["Target_URL"])
        scan_logger.log_activity(f"Creating map for scan {result.get('scanId', 'unknown')}")
        
        latitude = result.get("IP_Information", {}).get("Latitude")
        longitude = result.get("IP_Information", {}).get("Longitude")
        
        if latitude and longitude:
            scan_logger.log_activity(f"Creating map for coordinates: {latitude}, {longitude}")
            target_url = result["Target_URL"].replace("https://", "").replace("http://", "").replace("/", "_")
            waf_map = folium.Map(location=[latitude, longitude], zoom_start=6)

            # Format WAF info for popup
            waf_info = ", ".join(result['WAF_Detection_Result'])
            
            folium.Marker(
                [latitude, longitude],
                popup=f"<b>{result['Target_URL']}</b><br>WAF: {waf_info}<br>Location: {result['IP_Information']['Location']}<br>ISP: {result['IP_Information']['ISP']}",
                icon=folium.Icon(color='blue', icon='info-sign')
            ).add_to(waf_map)

            map_file = f"data/{target_url}_{result.get('scanId', 'unknown')}_map.html"
            waf_map.save(map_file)
            scan_logger.log_activity(f"Map saved to {map_file}")
            return map_file
        else:
            scan_logger.log_activity("No coordinates available for map creation")
            return None
    except Exception as e:
        scan_logger.log_activity(f"Error creating map: {str(e)}")
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

# import asyncio
# import json
# import socket
# import re
# import aiohttp
# import folium
# from geopy.geocoders import Nominatim
# from urllib.parse import urlparse
# import os
# import logging

# os.makedirs("data", exist_ok=True)

# # Set up logging
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#     handlers=[
#         logging.FileHandler("data/waf_scan.log"),
#         logging.StreamHandler()
#     ]
# )
# logger = logging.getLogger("WAFDetector")

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

# # Create data directory if it doesn't exist
# os.makedirs("data", exist_ok=True)

# async def get_ip(domain):
#     ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
#     if ip_pattern.match(domain):
#         logger.info(f"Input is already an IP address: {domain}")
#         return domain

#     try:
#         ip = socket.gethostbyname(domain)
#         logger.info(f"Resolved domain {domain} to IP {ip}")
#         return ip
#     except socket.gaierror as e:
#         logger.error(f"Failed to resolve domain {domain}: {str(e)}")
#         return "Unknown IP"

# async def get_geo_info(ip):
#     try:
#         logger.info(f"Getting geo information for IP: {ip}")
#         async with aiohttp.ClientSession() as session:
#             async with session.get(f"https://ipinfo.io/{ip}/json", timeout=10) as response:
#                 data = await response.json()
#                 city = data.get("city", "Unknown City")
#                 region = data.get("region", "Unknown Region")
#                 isp = data.get("org", "Unknown ISP")
                
#                 logger.info(f"IP info retrieved: {city}, {region}, {isp}")

#                 geolocator = Nominatim(user_agent="geoapi")
#                 location = geolocator.geocode(f"{city}, {region}")
#                 latitude, longitude = (location.latitude, location.longitude) if location else (None, None)
                
#                 if latitude and longitude:
#                     logger.info(f"Geocoded location: {latitude}, {longitude}")
#                 else:
#                     logger.warning(f"Could not geocode location for {city}, {region}")

#                 return city, region, isp, latitude, longitude
#     except Exception as e:
#         logger.error(f"Error getting geo information for {ip}: {str(e)}")
#         return "Unknown City", "Unknown Region", "Unknown ISP", None, None

# def detect_waf(headers):
#     detected_wafs = []
#     for waf, patterns in WAF_SIGNATURES.items():
#         if any(re.search(pattern, str(value), re.IGNORECASE) for pattern in patterns for value in headers.values()):
#             detected_wafs.append(waf)
#             logger.info(f"Detected WAF: {waf}")
    
#     if not detected_wafs:
#         logger.info("No WAF detected")
#         return "Unknown"
#     return detected_wafs

# def detect_server(headers):
#     for server, patterns in SERVER_SIGNATURES.items():
#         if any(re.search(pattern, str(value), re.IGNORECASE) for pattern in patterns for value in headers.values()):
#             logger.info(f"Detected server: {server}")
#             return server
    
#     logger.info("Could not identify server type")
#     return "Unknown Server"

# async def scan_target(url):
#     logger.info(f"Starting scan for target: {url}")
#     parsed_url = urlparse(url).netloc or url
#     ip_address = await get_ip(parsed_url)
    
#     if ip_address == "Unknown IP":
#         logger.error(f"Invalid domain or IP address: {parsed_url}")
#         return {"Target URL": url, "Error": "Invalid domain or IP address"}

#     if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip_address):
#         url = f"http://{ip_address}"
#         logger.info(f"Using IP directly as URL: {url}")

#     try:
#         async with aiohttp.ClientSession() as session:
#             logger.info(f"Sending request to {url}")
#             async with session.get(url, timeout=10) as response:
#                 status_code = response.status
#                 logger.info(f"Received response with status code: {status_code}")
                
#                 headers_log = {k: v for k, v in response.headers.items()}
#                 logger.info(f"Response headers: {json.dumps(headers_log)}")
                
#                 waf_result = detect_waf(response.headers)
#                 server_info = detect_server(response.headers)
#                 city, region, isp, latitude, longitude = await get_geo_info(ip_address)

#                 # Read scan logs
#                 with open("data/waf_scan.log", "r") as log_file:
#                     scan_logs = log_file.readlines()
                
#                 # Get only recent logs relevant to this scan
#                 relevant_logs = [log for log in scan_logs if parsed_url in log][-10:]  # Last 10 relevant log entries

#                 data = {
#                     "scanType": "WAFDetector",
#                     "Target_URL": parsed_url,
#                     "IP_Information": {
#                         "IPAddress": ip_address,
#                         "Location": f"{city}, {region}",
#                         "Latitude": latitude,
#                         "Longitude": longitude,
#                         "ISP": isp
#                     },
#                     "Status_Code": status_code,
#                     "WAF_Detection_Result": waf_result if isinstance(waf_result, list) else [waf_result],
#                     "Server": server_info,
#                     "Protection_Methods": "Rate Limiting, Captcha" if waf_result != "Unknown" else "None",
#                     "logs": relevant_logs
#                 }
                
#                 # Save result to JSON file
#                 target_name = parsed_url.replace(".", "_")
#                 result_file = f"data/{target_name}_result.json"
#                 with open(result_file, "w") as f:
#                     json.dump(data, f, indent=4)
                
#                 logger.info(f"Scan completed for {parsed_url}. Results saved to {result_file}")
#                 return data
                
#     except Exception as e:
#         error_msg = f"Error scanning {url}: {str(e)}"
#         logger.error(error_msg)
#         return {"Target URL": url, "Error": error_msg, "Scan Logs": get_recent_logs()}

# def get_recent_logs(num_lines=20):
#     """Get the most recent log entries"""
#     try:
#         with open("data/waf_scan.log", "r") as log_file:
#             logs = log_file.readlines()
#             return logs[-num_lines:]  # Return last n lines
#     except Exception as e:
#         return [f"Error reading logs: {str(e)}"]

# async def create_map(result):
#     try:
#         latitude = result.get("IP Information", {}).get("Latitude")
#         longitude = result.get("IP Information", {}).get("Longitude")
        
#         if latitude and longitude:
#             logger.info(f"Creating map for coordinates: {latitude}, {longitude}")
#             target_url = result["Target URL"].replace("https://", "").replace("http://", "").replace("/", "_")
#             waf_map = folium.Map(location=[latitude, longitude], zoom_start=6)

#             # Format WAF info for popup
#             waf_info = ", ".join(result['WAF Detection Result']) if isinstance(result['WAF Detection Result'], list) else result['WAF Detection Result']
            
#             folium.Marker(
#                 [latitude, longitude],
#                 popup=f"<b>{result['Target URL']}</b><br>WAF: {waf_info}<br>Location: {result['IP Information']['Location']}<br>ISP: {result['IP Information']['ISP']}",
#                 icon=folium.Icon(color='blue', icon='info-sign')
#             ).add_to(waf_map)

#             map_file = f"data/{target_url}_map.html"
#             waf_map.save(map_file)
#             logger.info(f"Map saved to {map_file}")
#             return map_file
#         else:
#             logger.warning("No coordinates available for map creation")
#             return None
#     except Exception as e:
#         logger.error(f"Error creating map: {str(e)}")
#         return None

# async def main():
#     """Example usage of the scanner"""
#     import sys
    
#     if len(sys.argv) > 1:
#         target = sys.argv[1]
#     else:
#         target = "example.com"  # Default target
    
#     logger.info(f"Starting WAF detection for {target}")
#     result = await scan_target(target)
    
#     if "Error" not in result:
#         map_file = await create_map(result)
#         if map_file:
#             logger.info(f"Map created at {map_file}")
    
#     # Output results to console
#     print(json.dumps(result, indent=4))
#     logger.info("Scan completed")

# if __name__ == "__main__":
#     asyncio.run(main())