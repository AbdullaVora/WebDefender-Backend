'''
Complete python-wappalyzer
'''

import warnings
import json
from Wappalyzer import Wappalyzer, WebPage
import os
from datetime import datetime
from urllib.parse import urlparse

def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or parsed.path

warnings.simplefilter("ignore")  # Suppress warnings globally

# Initialize Wappalyzer
wappalyzer = Wappalyzer.latest()

def analyze_website(url):
    """Analyze the given URL using Wappalyzer and save results in JSON."""
    try:
        webpage = WebPage.new_from_url(url)
        technologies = wappalyzer.analyze_with_versions_and_categories(webpage)

        if not technologies:
            return {"Error": "No technologies detected on the provided website."}

        categorized_tech = {}

        for tech, details in technologies.items():
            category = ", ".join(details.get("categories", ["Unknown"]))
            version = details.get("version", "N/A")

            if category not in categorized_tech:
                categorized_tech[category] = []

            categorized_tech[category].append({"Technology": tech, "Version": version})

        return {"Website": url, "Detected_Technologies": categorized_tech}

    except Exception as e:
        return {"Error": f"Could not analyze {url}: {e}"}


def save_to_json(url, filename="wappalyzer_scan.json"):
    """Save Wappalyzer scan results to a JSON file."""
    directory = extract_domain(url)
    os.makedirs(directory, exist_ok=True)
    filename = os.path.join(directory, f"{directory}_Tech_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

    scan_results = analyze_website(url)

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(scan_results, f, indent=4)

    print(f"\n📂 [bold green]Results saved to {filename}[/bold green]")


def tech(target):
    # Example usage
    website_url = target #"https://rnwmultimedia.edu.in"  # Change target here
    save_to_json(website_url, "wappalyzer_scan.json")

# tech("https://bmusurat.ac.in")