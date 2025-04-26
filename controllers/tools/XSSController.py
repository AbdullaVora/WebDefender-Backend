
# import time
# import logging
# import json
# from concurrent.futures import ThreadPoolExecutor
# from selenium import webdriver
# from selenium.webdriver.chrome.service import Service
# from selenium.webdriver.common.by import By
# from selenium.webdriver.support.ui import WebDriverWait
# from selenium.webdriver.support import expected_conditions as EC
# from selenium.webdriver.common.keys import Keys
# from selenium.common.exceptions import (
#     TimeoutException, NoAlertPresentException, NoSuchElementException, WebDriverException,
#     ElementNotInteractableException, UnexpectedAlertPresentException
# )
# from webdriver_manager.chrome import ChromeDriverManager


# def setup_logging():
#     logging.basicConfig(
#         filename="xss_scan.log",
#         filemode="a",
#         format="%(asctime)s - %(levelname)s - %(message)s",
#         level=logging.INFO
#     )


# def save_xss_result(target_url, parameter, status_code, payload):
#     result = {
#         "target_url": target_url,
#         "parameter": parameter,
#         "status_code": status_code,
#         "payload": payload
#     }
#     with open("output.txt", "a") as file:
#         file.write(json.dumps(result) + "\n")


# def should_skip_payload(payload):
#     SKIP_PATTERNS = ["autofocus", "onfocus"]
#     return any(pattern in payload.lower() for pattern in SKIP_PATTERNS)


# def get_all_inputs(driver):
#     return [el for el in driver.find_elements(By.CSS_SELECTOR, "input, textarea") if
#             el.is_displayed() and el.is_enabled()]


# def handle_alert(driver, target_url, parameter, payload):
#     try:
#         WebDriverWait(driver, 2).until(EC.alert_is_present())
#         alert = driver.switch_to.alert
#         logging.info(f"[XSS ALERT] Found: {alert.text}")
#         print(f"[🔥] XSS Alert Triggered: {alert.text}")

#         save_xss_result(target_url, parameter, 200, payload)

#         alert.dismiss()
#         return True
#     except (NoAlertPresentException, TimeoutException):
#         return False


# def inject_payloads(driver, fields, payloads, options, target_url):
#     alert_count = 0

#     for payload in payloads:
#         if should_skip_payload(payload):
#             print(f"[SKIPPING] Skipping potentially unstable payload: {payload}")
#             continue

#         print(f"[INFO] Injecting payload '{payload}' into fields")

#         for field in fields:
#             try:
#                 driver.get(target_url)
#                 fresh_fields = get_all_inputs(driver)
#                 target_field = fresh_fields[fields.index(field)]
#                 param_name = target_field.get_attribute("name") or "Unknown"

#                 target_field.clear()
#                 target_field.send_keys(payload + Keys.RETURN)
#                 time.sleep(1)

#                 if handle_alert(driver, target_url, param_name, payload):
#                     logging.info(f"Vulnerable field found with payload: {payload}")
#                     alert_count += 1

#                 if alert_count >= 3:
#                     print("[ALERT] Alert detected 3 times. Restarting browser...")
#                     alert_count = 0
#                     driver.quit()
#                     driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
#                     driver.get(target_url)
#                     time.sleep(1)
#             except UnexpectedAlertPresentException:
#                 print("[WARNING] Handling unexpected alert...")
#                 try:
#                     alert = driver.switch_to.alert
#                     print(f"[ALERT] Found: {alert.text}")
#                     alert.dismiss()
#                     time.sleep(1)
#                 except NoAlertPresentException:
#                     pass
#             except Exception as e:
#                 logging.error(f"Error injecting into field: {str(e)}")


# def scan_url(driver, target_url, payloads, options):
#     try:
#         driver.get(target_url)
#         time.sleep(1)
#         fields = get_all_inputs(driver)
#         field_names = [field.get_attribute('name') or field.get_attribute('id') or 'Unknown' for field in fields]
#         print(f"[INFO] Found {len(fields)} input fields => {field_names}")
#         inject_payloads(driver, fields, payloads, options, target_url)
#     except WebDriverException as e:
#         logging.error(f"Error accessing {target_url}: {str(e)}")
#         print(f"[ERROR] Failed to access {target_url}. Check if it's available.")


# def main():
#     setup_logging()
#     try:
#         with open("D:\WebDefender_Backend\WebDefender_API\helper\payloads\optimized_reflected_xss.txt", "r") as file:
#             payloads = [line.strip() for line in file if line.strip()]
#     except FileNotFoundError:
#         print("[ERROR] Payload file not found! Ensure 'optimized_reflected_xss.txt' exists.")
#         return

#     choice = input(
#         "Do you want to scan a single URL or multiple URLs from a file? (Enter 'single' or 'file'): ").strip().lower()
#     if choice == "single":
#         target_urls = [input("Enter the target URL: ").strip()]
#     elif choice == "file":
#         file_path = input("Enter the path to the URL file: ").strip()
#         try:
#             with open(file_path, "r") as file:
#                 target_urls = [line.strip() for line in file if line.strip()]
#         except FileNotFoundError:
#             print(f"[ERROR] URL file not found! Ensure '{file_path}' exists.")
#             return
#     else:
#         print("[ERROR] Invalid choice. Please enter 'single' or 'file'.")
#         return

#     options = webdriver.ChromeOptions()
#     options.add_argument("--headless")
#     options.add_argument("--no-sandbox")
#     options.add_argument("--disable-dev-shm-usage")
#     options.add_argument("--blink-settings=imagesEnabled=false")

#     driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

#     with ThreadPoolExecutor(max_workers=5) as executor:
#         futures = [executor.submit(scan_url, driver, url, payloads[:1000], options) for url in target_urls]
#         for future in futures:
#             future.result()


# if __name__ == "__main__":
#     start_time = time.time()
#     main()
#     end_time = time.time()
#     print(f"\n[⏱] Total Time Taken: {(end_time - start_time) / 60:.2f} min")

import time
import logging
import json
from concurrent.futures import ThreadPoolExecutor
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import (
    TimeoutException, NoAlertPresentException, NoSuchElementException, WebDriverException,
    ElementNotInteractableException, UnexpectedAlertPresentException
)
from webdriver_manager.chrome import ChromeDriverManager


def setup_logging():
    logging.basicConfig(
        filename="xss_scan.log",
        filemode="a",
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=logging.INFO
    )


def save_xss_result(target_url, parameter, status_code, payload):
    result = {
        "target_url": target_url,
        "parameter": parameter,
        "status_code": status_code,
        "payload": payload
    }
    with open("output.txt", "a") as file:
        file.write(json.dumps(result) + "\n")


def should_skip_payload(payload):
    SKIP_PATTERNS = ["autofocus", "onfocus"]
    return any(pattern in payload.lower() for pattern in SKIP_PATTERNS)


def get_all_inputs(driver):
    return [
        el for el in driver.find_elements(By.CSS_SELECTOR, "input, textarea")
        if el.is_displayed() and el.is_enabled()
    ]


def handle_alert(driver, target_url, parameter, payload):
    try:
        WebDriverWait(driver, 2).until(EC.alert_is_present())
        alert = driver.switch_to.alert
        logging.info(f"[XSS ALERT] Found: {alert.text}")
        print(f"[🔥] XSS Alert Triggered: {alert.text}")

        save_xss_result(target_url, parameter, 200, payload)

        alert.dismiss()
        return True
    except (NoAlertPresentException, TimeoutException):
        return False


def inject_payloads(driver, fields, payloads, options, target_url):
    alert_count = 0

    for payload in payloads:
        if should_skip_payload(payload):
            logging.info(f"[SKIPPING] Skipping unstable payload: {payload}")
            continue

        logging.info(f"[INFO] Injecting payload: {payload}")

        for field in fields:
            try:
                driver.get(target_url)
                fresh_fields = get_all_inputs(driver)
                target_field = fresh_fields[fields.index(field)]
                param_name = target_field.get_attribute("name") or "Unknown"

                target_field.clear()
                target_field.send_keys(payload + Keys.RETURN)
                time.sleep(1)

                if handle_alert(driver, target_url, param_name, payload):
                    logging.info(f"[SUCCESS] Payload triggered XSS: {payload}")
                    alert_count += 1

                if alert_count >= 3:
                    logging.info("[RESTART] Trigger limit reached, restarting browser.")
                    alert_count = 0
                    driver.quit()
                    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
                    driver.get(target_url)
                    time.sleep(1)
            except UnexpectedAlertPresentException:
                logging.warning("[WARNING] Unexpected alert appeared. Handling...")
                try:
                    alert = driver.switch_to.alert
                    logging.info(f"[ALERT] Found: {alert.text}")
                    alert.dismiss()
                    time.sleep(1)
                except NoAlertPresentException:
                    pass
            except Exception as e:
                logging.error(f"[ERROR] Failed to inject payload: {str(e)}")


def scan_url(driver, target_url, payloads, options):
    try:
        driver.get(target_url)
        time.sleep(1)
        fields = get_all_inputs(driver)
        field_names = [
            field.get_attribute('name') or field.get_attribute('id') or 'Unknown'
            for field in fields
        ]
        logging.info(f"[INFO] Found {len(fields)} input fields: {field_names}")
        inject_payloads(driver, fields, payloads, options, target_url)
    except WebDriverException as e:
        logging.error(f"[ERROR] Could not load {target_url}: {str(e)}")
        print(f"[❌] Failed to access {target_url}.")
