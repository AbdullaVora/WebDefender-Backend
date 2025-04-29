

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

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

from models.tools.XssModel import ScanRequest
from controllers.tools import XSSController
from config.database import get_db



router = APIRouter()


def get_chrome_driver(options):
    return webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)


import os

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
    options.add_argument("--blink-settings=imagesEnabled=false")

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


@router.get("/XssScan/results")
def get_scan_results():
    result_file = "output.txt"
    if not os.path.exists(result_file):
        return {"error": "No scan results found."}

    with open(result_file, "r") as file:
        results = [json.loads(line) for line in file if line.strip()]
    return {"results": results}



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
# from selenium.webdriver.chrome.options import Options
# from webdriver_manager.chrome import ChromeDriverManager
# from webdriver_manager.core.utils import ChromeType  # Add this import

# from models.tools.XssModel import ScanRequest
# from controllers.tools import XSSController
# from config.database import get_db

# router = APIRouter()

# def get_chrome_driver(options):
#     # Modified for Render compatibility
#     return webdriver.Chrome(
#         service=Service(
#             ChromeDriverManager(
#                 chrome_type=ChromeType.CHROMIUM  # Use Chromium instead of Chrome
#             ).install()
#         ),
#         options=options
#     )

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

#     # Configure Chrome options for Render environment
#     options = Options()
#     options.add_argument("--headless")
#     options.add_argument("--no-sandbox")  # Essential for Docker/container environments
#     options.add_argument("--disable-dev-shm-usage")  # Prevent /dev/shm issues
#     options.add_argument("--blink-settings=imagesEnabled=false")
#     options.add_argument("--disable-gpu")  # Disable GPU hardware acceleration
#     options.add_argument("--remote-debugging-port=9222")  # Enable remote debugging
    
#     # Additional reliability improvements
#     options.add_argument('--disable-extensions')
#     options.add_argument('--disable-infobars')
#     options.add_argument('--disable-browser-side-navigation')
#     options.add_argument('--disable-features=VizDisplayCompositor')

#     try:
#         driver = get_chrome_driver(options)
#     except Exception as e:
#         logging.error(f"Failed to initialize WebDriver: {str(e)}")
#         return {
#             "error": "Failed to initialize browser",
#             "details": str(e),
#             "scanStatus": "failed"
#         }

#     results = []

#     def custom_save_xss_result(target_url, parameter, status_code, payload):
#         result = {
#             "target_url": target_url,
#             "parameter": parameter,
#             "status_code": status_code,
#             "payload": payload
#         }
#         results.append(result)

#     XSSController.save_xss_result = custom_save_xss_result

#     try:
#         for url in urls_to_scan:
#             XSSController.scan_url(driver, url, payloads, options)
#     except Exception as e:
#         logging.error(f"Scan failed: {str(e)}")
#         return {
#             "error": "Scan failed",
#             "details": str(e),
#             "scanStatus": "failed"
#         }
#     finally:
#         driver.quit()

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

#     if db is not None:
#         try:
#             await db.Xss_Report.insert_one(main_result.copy())
#         except Exception as e:
#             logging.error(f"Error saving to MongoDB: {e}")

#     return main_result

# @router.get("/XssScan/results")
# def get_scan_results():
#     result_file = "output.txt"
#     if not os.path.exists(result_file):
#         return {"error": "No scan results found."}

#     with open(result_file, "r") as file:
#         results = [json.loads(line) for line in file if line.strip()]
#     return {"results": results}