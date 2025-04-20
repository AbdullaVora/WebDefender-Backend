# xss_routes.py

from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import List, Optional, Dict
from concurrent.futures import ThreadPoolExecutor
import time
import os
import json

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from models.tools.XssModel import ScanRequest

from controllers.tools.XSSController import scan_url, setup_logging  # your existing logic file
from config.database import db

router = APIRouter()


def get_chrome_driver(options):
    return webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)


def load_default_payloads():
    with open("D:/WebDefender_Backend/WebDefender_API/helper/payloads/optimized_reflected_xss.txt", "r") as file:
        return [line.strip() for line in file if line.strip()]


@router.post("/DOM-BasedXss")
async def run_xss_scan(request_data: ScanRequest):
    setup_logging()

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

    def custom_save_xss_result(target_url, parameter, status_code, payload):
        result = {
            "target_url": target_url,
            "parameter": parameter,
            "status_code": status_code,
            "payload": payload
        }
        results.append(result)

    # Monkey patch the original save_xss_result function
    import controllers.tools.XSSController as xss_controller
    xss_controller.save_xss_result = custom_save_xss_result

    for url in urls_to_scan:
        scan_url(driver, url, payloads, options)

    driver.quit()

    main_result = {
        "scanType" : "DOM-BasedXss",
        "user_id": request_data.userId,
        "message": "XSS scan completed",
        "targets": urls_to_scan,
        "vulnerabilities": results
    }

    if db is not None:
        try:
            mongo_result = main_result.copy()  # Ensure it's serializable
            insert_result = await db.Xss_Report.insert_one(mongo_result)
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
