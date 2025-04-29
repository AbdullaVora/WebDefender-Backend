# from fastapi import APIRouter
# from pydantic import BaseModel
# from typing import List, Optional
# from concurrent.futures import ThreadPoolExecutor
# from datetime import datetime
# import time
# import os
# import json
# import logging
# from io import StringIO

# from selenium import webdriver
# from selenium.webdriver.chrome.service import Service
# from webdriver_manager.chrome import ChromeDriverManager

# from models.tools.XssModel import ScanRequest
# from controllers.tools import XSSController
# from config.database import get_db



# router = APIRouter()


# def get_chrome_driver(options):
#     return webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)


# import os

# def load_default_payloads():
#     payloads_path = os.path.join("helper", "payloads", "optimized_reflected_xss.txt")
#     with open(payloads_path, "r") as file:
#         return [line.strip() for line in file if line.strip()]

# @router.post("/DOM-BasedXss")
# async def run_xss_scan(request_data: ScanRequest):

#     db = get_db()
    
#     # Setup in-memory logging
#     log_stream = StringIO()
#     stream_handler = logging.StreamHandler(log_stream)
#     stream_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
#     logging.getLogger().addHandler(stream_handler)
#     logging.getLogger().setLevel(logging.INFO)

#     XSSController.setup_logging()

#     urls_to_scan = []
#     if request_data.custom and request_data.custom.urls:
#         urls_to_scan = request_data.custom.urls
#     elif request_data.domain:
#         urls_to_scan = [request_data.domain]
#     else:
#         return {"error": "No valid domain or URL list provided."}

#     payloads = (
#         request_data.custom.payloads
#         if request_data.custom and request_data.custom.payloads
#         else load_default_payloads()
#     )

#     options = webdriver.ChromeOptions()
#     options.add_argument("--headless")
#     options.add_argument("--no-sandbox")
#     options.add_argument("--disable-dev-shm-usage")
#     options.add_argument("--blink-settings=imagesEnabled=false")

#     driver = get_chrome_driver(options)

#     results = []

#     # Override save_xss_result to append to results instead of file
#     def custom_save_xss_result(target_url, parameter, status_code, payload):
#         result = {
#             "target_url": target_url,
#             "parameter": parameter,
#             "status_code": status_code,
#             "payload": payload
#         }
#         results.append(result)

#     XSSController.save_xss_result = custom_save_xss_result  # Monkey patch

#     for url in urls_to_scan:
#         XSSController.scan_url(driver, url, payloads, options)

#     driver.quit()

#     # Flush and get logs
#     stream_handler.flush()
#     scan_logs = log_stream.getvalue()
#     logging.getLogger().removeHandler(stream_handler)

#     main_result = {
#         "scanType": "DOM-BasedXss",
#         "userId": request_data.userId,
#         "message": "XSS scan completed",
#         "targets": urls_to_scan,
#         "vulnerabilities": results,
#         "scanLogs": scan_logs,
#         "created_time": datetime.utcnow().isoformat(),
#         "scanStatus": "success"
#     }

#     # Optional MongoDB save
#     if db is not None:
#         try:
#             await db.Xss_Report.insert_one(main_result.copy())
#         except Exception as e:
#             print(f"[❌] Error saving to MongoDB: {e}")

#     return main_result


# @router.get("/XssScan/results")
# def get_scan_results():
#     result_file = "output.txt"
#     if not os.path.exists(result_file):
#         return {"error": "No scan results found."}

#     with open(result_file, "r") as file:
#         results = [json.loads(line) for line in file if line.strip()]
#     return {"results": results}


from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import time
import os
import json
import logging
from io import StringIO
import platform
import subprocess

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

from models.tools.XssModel import ScanRequest
from controllers.tools import XSSController
from config.database import get_db


router = APIRouter()


def get_chrome_driver(options):
    """
    Create and return a Chrome WebDriver with configured options.
    This function handles different environments (local vs cloud hosting like Render).
    """
    # Check if we're in a cloud environment (most likely Render)
    is_render = "RENDER" in os.environ
    
    # Add essential options for headless environments
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    
    if is_render:
        # Try to install Chrome if it's not available (Render specific)
        try:
            # Check if Chrome is already installed
            chrome_installed = False
            try:
                subprocess.run(['google-chrome', '--version'], 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE, 
                               check=True)
                chrome_installed = True
            except (subprocess.SubprocessError, FileNotFoundError):
                pass
            
            if not chrome_installed:
                logging.info("Chrome not found, attempting to install...")
                # Log the attempt to install Chrome
                logging.info("Chrome installation may require additional setup in Render")
        except Exception as e:
            logging.error(f"Error checking/installing Chrome: {str(e)}")
        
        # Try to find Chrome binary in common locations
        chrome_paths = [
            '/usr/bin/google-chrome',
            '/usr/bin/google-chrome-stable',
            '/usr/bin/chromium',
            '/usr/bin/chromium-browser',
            '/opt/google/chrome/chrome'
        ]
        
        # Set binary location if found
        for path in chrome_paths:
            if os.path.exists(path):
                options.binary_location = path
                logging.info(f"Found Chrome binary at: {path}")
                break
    
    try:
        # Create the driver
        return webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    except Exception as e:
        logging.error(f"WebDriver creation error: {str(e)}")
        # Fallback to a more explicit error with troubleshooting info
        error_msg = f"Failed to create Chrome WebDriver: {str(e)}"
        if is_render:
            error_msg += "\nThis may be due to Chrome not being installed on the Render environment."
            error_msg += "\nPlease update your Render configuration to install Chrome."
        raise RuntimeError(error_msg)


def load_default_payloads():
    payloads_path = os.path.join("helper", "payloads", "optimized_reflected_xss.txt")
    with open(payloads_path, "r") as file:
        return [line.strip() for line in file if line.strip()]


@router.post("/DOM-BasedXss")
async def run_xss_scan(request_data: ScanRequest):
    db = get_db()
    
    # Setup in-memory logging
    log_stream = StringIO()
    stream_handler = logging.StreamHandler(log_stream)
    stream_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logging.getLogger().addHandler(stream_handler)
    logging.getLogger().setLevel(logging.INFO)

    XSSController.setup_logging()

    urls_to_scan = []
    if request_data.custom and request_data.custom.urls:
        urls_to_scan = request_data.custom.urls
    elif request_data.domain:
        urls_to_scan = [request_data.domain]
    else:
        return {"error": "No valid domain or URL list provided."}

    payloads = (
        request_data.custom.payloads
        if request_data.custom and request_data.custom.payloads
        else load_default_payloads()
    )

    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--blink-settings=imagesEnabled=false")
    
    try:
        driver = get_chrome_driver(options)
        
        results = []

        # Override save_xss_result to append to results instead of file
        def custom_save_xss_result(target_url, parameter, status_code, payload):
            result = {
                "target_url": target_url,
                "parameter": parameter,
                "status_code": status_code,
                "payload": payload
            }
            results.append(result)

        XSSController.save_xss_result = custom_save_xss_result  # Monkey patch

        for url in urls_to_scan:
            XSSController.scan_url(driver, url, payloads, options)

        driver.quit()

        # Flush and get logs
        stream_handler.flush()
        scan_logs = log_stream.getvalue()
        logging.getLogger().removeHandler(stream_handler)

        main_result = {
            "scanType": "DOM-BasedXss",
            "userId": request_data.userId,
            "message": "XSS scan completed",
            "targets": urls_to_scan,
            "vulnerabilities": results,
            "scanLogs": scan_logs,
            "created_time": datetime.utcnow().isoformat(),
            "scanStatus": "success"
        }

        # Optional MongoDB save
        if db is not None:
            try:
                await db.Xss_Report.insert_one(main_result.copy())
            except Exception as e:
                print(f"[❌] Error saving to MongoDB: {e}")

        return main_result
        
    except Exception as e:
        # Handle Chrome WebDriver setup failures
        logging.error(f"Failed to run XSS scan: {str(e)}")
        stream_handler.flush()
        error_logs = log_stream.getvalue()
        logging.getLogger().removeHandler(stream_handler)
        
        error_result = {
            "scanType": "DOM-BasedXss",
            "userId": request_data.userId,
            "message": f"XSS scan failed: {str(e)}",
            "targets": urls_to_scan,
            "vulnerabilities": [],
            "scanLogs": error_logs,
            "created_time": datetime.utcnow().isoformat(),
            "scanStatus": "failed",
            "error": str(e)
        }
        
        # Still try to save the error report
        if db is not None:
            try:
                await db.Xss_Report.insert_one(error_result.copy())
            except Exception as mongo_err:
                print(f"[❌] Error saving error report to MongoDB: {mongo_err}")
        
        return error_result


@router.get("/XssScan/results")
def get_scan_results():
    result_file = "output.txt"
    if not os.path.exists(result_file):
        return {"error": "No scan results found."}

    with open(result_file, "r") as file:
        results = [json.loads(line) for line in file if line.strip()]
    return {"results": results}