'''
Complete
'''

import requests
import json
import os
from datetime import datetime
from urllib.parse import urlparse

def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or parsed.path



def check_http_security_headers(url):
    directory = extract_domain(url)
    os.makedirs(directory, exist_ok=True)
    json_filename = os.path.join(directory, f"{directory}_Http-Sec_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        def get_status(header_name, valid_values=None):
            """Returns status based on header existence and value validation."""
            if header_name in headers:
                value = headers[header_name]
                if valid_values:
                    return "Yes" if value in valid_values else "Unknown"
                return value
            return "No"

        security_checks = {
            "Content-Security-Policy": get_status("Content-Security-Policy"),
            "Strict-Transport-Security": get_status("Strict-Transport-Security"),
            "X-Content-Type-Options": get_status("X-Content-Type-Options", ["nosniff"]),
            "X-Frame-Options": get_status("X-Frame-Options", ["DENY", "SAMEORIGIN"]),
            "X-XSS-Protection": get_status("X-XSS-Protection", ["1; mode=block"]),
            "Referrer-Policy": get_status("Referrer-Policy"),
            "Permissions-Policy": get_status("Permissions-Policy"),
            "Expect-CT": get_status("Expect-CT"),
        }

        result = {
            "url": url,
            "security_headers": security_checks,
        }

        print("\n🔐 HTTP Security Headers Check for:", url)
        print("=" * 60)
        for header, status in security_checks.items():
            print(f"🔹 {header}: {status}")
        print("=" * 60)

        # Save results to JSON file
        with open(json_filename, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=4)

        print(f"\n📂 Results saved to {json_filename}")

    except requests.exceptions.RequestException as e:
        print(f"⚠️ Error: Could not fetch headers from {url} - {e}")


def http_sec(target):
    # Example Usage
    website = target #"https://kpa.io"
    check_http_security_headers(website)
