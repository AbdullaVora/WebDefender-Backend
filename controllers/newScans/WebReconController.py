import concurrent.futures
import traceback
import os
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, List, Any
import glob
import json
import shutil  # Add this import at the top with other imports


# Import specific functions from each tool module
from helper.newScans.webRecon.Tool.Cookies import cookie as check_cookies
from helper.newScans.webRecon.Tool.DNS import DNS as check_dns
from helper.newScans.webRecon.Tool.DNSSEC import dnssec as check_dnssec
from helper.newScans.webRecon.Tool.Email_Security import email_sec as check_email_security
from helper.newScans.webRecon.Tool.headers import headers as check_headers
from helper.newScans.webRecon.Tool.HSTS import hsts as check_hsts
from helper.newScans.webRecon.Tool.http_security import http_sec as check_http_security
from helper.newScans.webRecon.Tool.SecFile import secfile  as check_sec_file
from helper.newScans.webRecon.Tool.Sitemap import sitemap as check_sitemap
from helper.newScans.webRecon.Tool.Spider import spider as crawl_website
from helper.newScans.webRecon.Tool.ssl_tls import analyze_ssl_tls  as check_ssl_tls
from helper.newScans.webRecon.Tool.Tech import tech as check_tech
from helper.newScans.webRecon.Tool.WAF import Waf as check_waf
from helper.newScans.webRecon.Tool.WHOIS import whois_res as check_whois
from helper.newScans.webRecon.Tool.ZoneTransfer import zone_tr as check_zone_transfer

from models.newScans.WebReconModel import ToolResult, ScanResponse

def extract_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc or parsed.path


def run_tool(tool_func, tool_name: str, target: str) -> Dict[str, Any]:
    try:
        result = tool_func(target)
        
        # Handle file data collection
        directory = extract_domain(target)
        file_pattern = f"{directory}/{directory}_{tool_name}_*.json"
        files = glob.glob(file_pattern)
        
        file_data = {}
        if files:
            try:
                with open(files[-1], 'r') as f:
                    loaded_data = json.load(f)
                    # Convert list to dict if needed
                    if isinstance(loaded_data, list):
                        file_data = {"results": loaded_data}
                    else:
                        file_data = loaded_data
            except json.JSONDecodeError:
                file_data = {"error": "Failed to parse output file"}
            except Exception as e:
                file_data = {"error": f"File read error: {str(e)}"}
                
        return {
            "tool_name": tool_name,
            "status": "success",
            "data": result if isinstance(result, dict) else {"result": result},
            "file_data": file_data
        }
    except Exception as e:
        return {
            "tool_name": tool_name,
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc(),
            "data": {},
            "file_data": {}
        }

# def perform_scan(target: str) -> ScanResponse:
#     # Create output directory
#     directory = extract_domain(target)
#     os.makedirs(directory, exist_ok=True)
    
#     # List of tools to run (as (function, name) tuples)
#     tools = [
#         (check_cookies, "Cookies"),
#         (check_dns, "DNS"),
#         (check_dnssec, "DNSSEC"),
#         (check_email_security, "Email_Security"),
#         (check_headers, "headers"),
#         (check_hsts, "HSTS"),
#         (check_http_security, "http_security"),
#         (check_sec_file, "SecFile"),
#         (check_sitemap, "Sitemap"),
#         (crawl_website, "Spider"),
#         (check_ssl_tls, "ssl_tls"),
#         (check_tech, "Tech"),
#         (check_waf, "WAF"),
#         (check_whois, "WHOIS"),
#         (check_zone_transfer, "ZoneTransfer")
#     ]
    
#     results = []
#     merged_data = {}  # This will store all the merged data from files
    
#     with concurrent.futures.ThreadPoolExecutor() as executor:
#         futures = {
#             executor.submit(run_tool, tool_func, tool_name, target): (tool_func, tool_name)
#             for tool_func, tool_name in tools
#         }
        
#         for future in concurrent.futures.as_completed(futures):
#             tool_result = future.result()
#             results.append(tool_result)
            
#             # If the tool generated file data, add it to merged_data
#             if tool_result.get('file_data'):
#                 merged_data[tool_result['tool_name']] = tool_result['file_data']
    
#     # Create the response with both individual results and merged data
#     response = ScanResponse(
#         target=target,
#         status="completed",
#         results=[ToolResult(**result) for result in results],
#         merged_data=merged_data,  # Add the merged data to the response
#         timestamp=datetime.now().isoformat()
#     )

#     return response

def perform_scan(target: str) -> ScanResponse:
    # Create output directory
    directory = extract_domain(target)
    os.makedirs(directory, exist_ok=True)
    
    try:
        # List of tools to run (as (function, name) tuples)
        tools = [
            (check_cookies, "Cookies"),
            (check_dns, "DNS"),
            (check_dnssec, "DNSSEC"),
            (check_email_security, "Email_Security"),
            (check_headers, "headers"),
            (check_hsts, "HSTS"),
            (check_http_security, "http_security"),  # Fixed typo in variable name
            (check_sec_file, "SecFile"),
            (check_sitemap, "Sitemap"),
            (crawl_website, "Spider"),
            (check_ssl_tls, "ssl_tls"),
            (check_tech, "Tech"),
            (check_waf, "WAF"),
            (check_whois, "WHOIS"),
            (check_zone_transfer, "ZoneTransfer")
        ]
        
        results = []
        merged_data = {}  # This will store all the merged data from files
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = {
                executor.submit(run_tool, tool_func, tool_name, target): (tool_func, tool_name)
                for tool_func, tool_name in tools
            }
            
            for future in concurrent.futures.as_completed(futures):
                tool_result = future.result()
                results.append(tool_result)
                
                # If the tool generated file data, add it to merged_data
                if tool_result.get('file_data'):
                    merged_data[tool_result['tool_name']] = tool_result['file_data']
        
        # Create the response before cleaning up
        response = ScanResponse(
            target=target,
            status="completed",
            results=[ToolResult(**result) for result in results],
            merged_data=merged_data,
            timestamp=datetime.now().isoformat()
        )
        
        return response
        
    finally:
        # This block will run whether the scan succeeds or fails
        try:
            if os.path.exists(directory):
                shutil.rmtree(directory)
                print(f"Successfully deleted output directory: {directory}")
        except Exception as e:
            print(f"Warning: Could not delete output directory {directory}: {str(e)}")
            # You might want to log this error properly in production

# import time
# import concurrent.futures
# import traceback
# from typing import Dict, List, Optional, Any

# from models.newScans.WebReconModel import ToolResult, ScanResponse

# # Import tool modules
# from helper.newScans.webRecon.Tool.Cookies import cookie
# from helper.newScans.webRecon.Tool.DNS import DNS
# from helper.newScans.webRecon.Tool.DNSSEC import dnssec
# from helper.newScans.webRecon.Tool.Email_Security import email_sec
# from helper.newScans.webRecon.Tool.headers import headers
# from helper.newScans.webRecon.Tool.HSTS import hsts
# from helper.newScans.webRecon.Tool.http_security import http_sec
# from helper.newScans.webRecon.Tool.SecFile import secfile
# from helper.newScans.webRecon.Tool.Sitemap import sitemap
# from helper.newScans.webRecon.Tool.Spider import spider
# from helper.newScans.webRecon.Tool.ssl_tls import analyze_ssl_tls
# from helper.newScans.webRecon.Tool.Tech import tech
# from helper.newScans.webRecon.Tool.WAF import Waf
# from helper.newScans.webRecon.Tool.WHOIS import whois_res
# from helper.newScans.webRecon.Tool.ZoneTransfer import zone_tr

# class ScannerController:
#     def __init__(self):
#         # Map tool names to functions
#         self.tools = {
#             "cookies": cookie,
#             "dns": DNS,
#             "dnssec": dnssec,
#             "email_security": email_sec,
#             "headers": headers,
#             "hsts": hsts,
#             "http_security": http_sec,
#             "security_files": secfile,
#             "sitemap": sitemap,
#             "spider": spider,
#             "ssl_tls": self._wrapper_ssl_tls,  # Use wrapper to ensure proper result format
#             "technologies": tech,
#             "waf": Waf,
#             "whois": self._wrapper_whois,  # Use wrapper for WHOIS to handle issues
#             "zone_transfer": zone_tr,
#         }
    
#     def get_available_tools(self) -> List[str]:
#         """Get list of available tool names"""
#         return list(self.tools.keys())
    
#     def _wrapper_whois(self, target: str) -> Dict[str, Any]:
#         """
#         Wrapper for WHOIS to handle potential module issues
#         """
#         try:
#             # Try to use the existing whois_res function
#             result = whois_res(target)
#             if isinstance(result, dict):
#                 return result
#             else:
#                 return {"whois_result": str(result)}
#         except AttributeError:
#             # If the python-whois package is installed but used differently
#             try:
#                 import whois
#                 w = whois.query(target)  # Some versions use query instead of whois
#                 if w:
#                     return {
#                         "domain_name": w.name,
#                         "registrar": getattr(w, "registrar", "Unknown"),
#                         "creation_date": str(getattr(w, "creation_date", "Unknown")),
#                         "expiration_date": str(getattr(w, "expiration_date", "Unknown")),
#                         "name_servers": getattr(w, "name_servers", []),
#                     }
#                 return {"message": "No WHOIS data found"}
#             except Exception as e:
#                 # As a last resort, try to use the command-line whois tool
#                 try:
#                     import subprocess
#                     result = subprocess.run(["whois", target], capture_output=True, text=True)
#                     return {"raw_whois": result.stdout}
#                 except Exception as cmd_error:
#                     return {"error": f"Could not retrieve WHOIS data: {str(e)}, Command line fallback failed: {str(cmd_error)}"}
    
#     def _wrapper_ssl_tls(self, target: str) -> Dict[str, Any]:
#         """
#         Wrapper for SSL/TLS analysis to ensure result is a dictionary
#         """
#         try:
#             result = analyze_ssl_tls(target)
#             # If result is already a dict, return it
#             if isinstance(result, dict):
#                 return result
#             # If result is a tuple, convert to dictionary
#             elif isinstance(result, tuple):
#                 return {
#                     "host": target,
#                     "ssl_info": result[0] if len(result) > 0 else None,
#                     "additional_info": result[1] if len(result) > 1 else None
#                 }
#             # For any other type, convert to string in a dictionary
#             else:
#                 return {"ssl_tls_result": str(result)}
#         except Exception as e:
#             return {"error": f"SSL/TLS analysis failed: {str(e)}"}
    
#     def run_tool(self, tool_name: str, target: str) -> ToolResult:
#         """
#         Run a single security tool and return its result
#         """
#         try:
#             print(f"[+] Running {tool_name}")
#             tool_func = self.tools[tool_name]
#             result = tool_func(target)
            
#             # Ensure result is a dictionary
#             if result is None:
#                 result = {"message": f"{tool_name} completed but returned no data"}
#             elif not isinstance(result, dict):
#                 result = {f"{tool_name}_result": str(result)}
                
#             print(f"[+] {tool_name} completed\n")
#             return ToolResult(success=True, data=result)
#         except Exception as e:
#             error_msg = f"Error running {tool_name}: {str(e)}\n{traceback.format_exc()}"
#             print(f"[-] {error_msg}")
#             return ToolResult(success=False, error=error_msg)
    
#     def run_scan(self, target: str, tools: Optional[List[str]] = None) -> ScanResponse:
#         """
#         Run security scan on the target website
#         """
#         start_time = time.time()
#         results = {}
        
#         # Get all available tools if none specified
#         if not tools:
#             tools = self.get_available_tools()
        
#         # Run tools in parallel
#         with concurrent.futures.ThreadPoolExecutor() as executor:
#             future_to_tool = {
#                 executor.submit(self.run_tool, tool, target): tool 
#                 for tool in tools if tool in self.tools
#             }
            
#             for future in concurrent.futures.as_completed(future_to_tool):
#                 tool = future_to_tool[future]
#                 try:
#                     results[tool] = future.result()
#                 except Exception as e:
#                     results[tool] = ToolResult(
#                         success=False,
#                         error=f"Exception running {tool}: {str(e)}"
#                     )
        
#         # Add entries for requested tools that don't exist
#         for tool in tools:
#             if tool not in self.tools and tool not in results:
#                 results[tool] = ToolResult(
#                     success=False,
#                     error=f"Tool '{tool}' not found"
#                 )
        
#         scan_time = time.time() - start_time
        
#         return ScanResponse(
#             target=target,
#             results=results,
#             scan_time=scan_time
#         )