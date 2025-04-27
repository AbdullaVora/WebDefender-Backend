# # xss_routes.py

# from fastapi import APIRouter, Request
# from pydantic import BaseModel
# from typing import List, Optional, Dict
# from concurrent.futures import ThreadPoolExecutor
# import time
# import os
# import json
# from datetime import datetime

# from selenium import webdriver
# from selenium.webdriver.chrome.service import Service
# from webdriver_manager.chrome import ChromeDriverManager
# from models.tools.XssModel import ScanRequest

# from controllers.tools.XSSController import scan_url, setup_logging  # your existing logic file
# from config.database import db

# router = APIRouter()


# def get_chrome_driver(options):
#     return webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)


# def load_default_payloads():
#     with open("D:/WebDefender_Backend/WebDefender_API/helper/payloads/optimized_reflected_xss.txt", "r") as file:
#         return [line.strip() for line in file if line.strip()]


# @router.post("/DOM-BasedXss")
# async def run_xss_scan(request_data: ScanRequest):
#     setup_logging()

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

#     def custom_save_xss_result(target_url, parameter, status_code, payload):
#         result = {
#             "target_url": target_url,
#             "parameter": parameter,
#             "status_code": status_code,
#             "payload": payload
#         }
#         results.append(result)

#     # Monkey patch the original save_xss_result function
#     import controllers.tools.XSSController as xss_controller
#     xss_controller.save_xss_result = custom_save_xss_result

#     for url in urls_to_scan:
#         scan_url(driver, url, payloads, options)

#     driver.quit()

#     main_result = {
#         "scanType" : "DOM-BasedXss",
#         "user_id": request_data.userId,
#         "message": "XSS scan completed",
#         "targets": urls_to_scan,
#         "vulnerabilities": results,
#         "created_time": datetime.utcnow().isoformat(), 
#         "scanStatus": "success"
        
#     }

#     if db is not None:
#         try:
#             mongo_result = main_result.copy()  # Ensure it's serializable
#             insert_result = await db.Xss_Report.insert_one(mongo_result)
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
#         "user_id": request_data.userId,
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
    # For Render environment
    if "RENDER" in os.environ:
        # Chrome is pre-installed on Render (or installed via build script)
        chrome_path = "/usr/bin/google-chrome"  # or the correct path on Render
        options.binary_location = chrome_path
        
        # Use chromedriver path directly (consider adding to your project)
        chrome_driver_path = os.environ.get("CHROMEDRIVER_PATH", "/usr/bin/chromedriver")
        return webdriver.Chrome(service=Service(chrome_driver_path), options=options)
    else:
        # Local development still uses ChromeDriverManager
        return webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

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
    options.add_argument("--disable-gpu")  # Important for cloud environments
    options.add_argument("--blink-settings=imagesEnabled=false")
    options.add_argument("--disable-extensions")
    options.add_argument("--remote-debugging-port=9222")

    # Additional options for Render specifically
    if "RENDER" in os.environ:
        options.add_argument("--disable-setuid-sandbox")
        options.add_argument("--single-process")  # Helps with memory issues
        logging.info("Running in Render environment with specialized Chrome options")

    try:
        driver = get_chrome_driver(options)
        logging.info("Chrome WebDriver initialized successfully")
    except Exception as e:
        logging.error(f"Failed to initialize Chrome WebDriver: {str(e)}")
        return {
            "scanType": "DOM-BasedXss",
            "user_id": request_data.userId,
            "message": f"Failed to initialize Chrome WebDriver: {str(e)}",
            "targets": urls_to_scan,
            "vulnerabilities": [],
            "scanLogs": log_stream.getvalue(),
            "created_time": datetime.utcnow().isoformat(),
            "scanStatus": "failed"
        }

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
        logging.info(f"Found XSS vulnerability: {result}")

    # Store original function to restore later if needed
    original_save_xss_result = XSSController.save_xss_result
    XSSController.save_xss_result = custom_save_xss_result  # Monkey patch

    try:
        for url in urls_to_scan:
            try:
                logging.info(f"Scanning URL: {url}")
                XSSController.scan_url(driver, url, payloads, options)
            except Exception as e:
                logging.error(f"Error scanning URL {url}: {str(e)}")
    except Exception as e:
        logging.error(f"Error during scan: {str(e)}")
    finally:
        # Restore original function
        XSSController.save_xss_result = original_save_xss_result
        
        # Always quit the driver
        try:
            driver.quit()
            logging.info("Chrome WebDriver closed successfully")
        except Exception as e:
            logging.error(f"Error closing Chrome WebDriver: {str(e)}")

    # Flush and get logs
    stream_handler.flush()
    scan_logs = log_stream.getvalue()
    logging.getLogger().removeHandler(stream_handler)

    main_result = {
        "scanType": "DOM-BasedXss",
        "user_id": request_data.userId,
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
            logging.info("Results saved to MongoDB")
        except Exception as e:
            logging.error(f"Error saving to MongoDB: {str(e)}")

    return main_result

@router.get("/XssScan/results")
def get_scan_results():
    result_file = "output.txt"
    if not os.path.exists(result_file):
        return {"error": "No scan results found."}

    with open(result_file, "r") as file:
        results = [json.loads(line) for line in file if line.strip()]
    return {"results": results}
