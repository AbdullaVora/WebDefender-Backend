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
    # ... rest of your signatures
}

SERVER_SIGNATURES = {
    "Apache": [r'apache'],
    "Nginx": [r'nginx'],
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