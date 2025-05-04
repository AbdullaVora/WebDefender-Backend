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


def check_hsts(url):
    directory = extract_domain(url)
    os.makedirs(directory, exist_ok=True)
    json_filename = os.path.join(directory, f"{directory}_HSTS_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

    try:
        # Ensure the URL starts with HTTPS
        if not url.startswith("https://"):
            url = "https://" + url

        # Send request and get headers
        response = requests.get(url, timeout=5)
        headers = response.headers

        # Check for HSTS
        hsts_header = headers.get("Strict-Transport-Security")

        result = {
            "url": url,
            "hsts_enabled": bool(hsts_header),
            "hsts_details": {},
        }

        print("\n🔐 HSTS (HTTP Strict Transport Security) Check")
        print("=" * 60)
        print(f"🌐 Scanned Website: {url}\n")

        if hsts_header:
            print(f"✅ HSTS is ENABLED with the following settings:\n")
            directives = hsts_header.split(";")

            for directive in directives:
                directive = directive.strip()
                if directive.startswith("max-age"):
                    max_age = directive.split("=")[-1]
                    print(f"   📌 max-age: {max_age} seconds (Duration)")
                    result["hsts_details"]["max-age"] = max_age
                elif directive == "includeSubDomains":
                    print(f"   📌 includeSubDomains: ✅ Yes (Applies to all subdomains)")
                    result["hsts_details"]["includeSubDomains"] = True
                elif directive == "preload":
                    print(f"   📌 preload: ✅ Yes (Submitted for Chrome preload list)")
                    result["hsts_details"]["preload"] = True
                else:
                    print(f"   ⚠️ Unknown directive: {directive}")
                    result["hsts_details"]["unknown_directives"] = directive
        else:
            print("❌ HSTS is NOT enabled for this website.")
            print("ℹ️  HSTS helps prevent man-in-the-middle attacks and forces secure connections.")
            print("   👉 Consider adding: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`")

        print("=" * 60)

        # Save to JSON file
        with open(json_filename, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=4)

        print(f"\n📂 Results saved to {json_filename}")

    except requests.exceptions.RequestException as e:
        print(f"⚠️ Error: Could not fetch HSTS information from {url} - {e}")


def hsts(target):
    # Example Usage
    website = target #"https://pixiv.net"
    check_hsts(website)

# hsts('https://pixiv.net')