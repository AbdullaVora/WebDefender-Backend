import requests
import json
import os
from datetime import datetime
from urllib.parse import urlparse

def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or parsed.path


def cookie(target):
    url = target
    session = requests.Session()
    response = session.get(url)

    # Extract cookies into a dictionary
    cookies_dict = {cookie.name: cookie.value for cookie in session.cookies}
    # save file and create Directory
    directory = extract_domain(target)
    os.makedirs(directory, exist_ok=True)
    filename = os.path.join(directory, f"{directory}_Cookies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

    # Save to JSON file
    with open(filename, "w") as f:
        json.dump(cookies_dict, f, indent=4)

    print("Cookies saved to pixiv_cookies.json")


# cookie('https://pixiv.net')