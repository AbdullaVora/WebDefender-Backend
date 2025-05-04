'''
    Complete
'''


import dns.resolver
import json
import os
from datetime import datetime
from urllib.parse import urlparse

def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or parsed.path

def get_dns_records(domain):
    """Fetch DNS records for the given domain from multiple resolvers."""
    dns_servers = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
    records = {}
    record_types = ["A", "AAAA", "MX", "NS", "CNAME", "TXT"]

    for rtype in record_types:
        all_answers = set()
        for server in dns_servers:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server]
            try:
                answers = resolver.resolve(domain, rtype, lifetime=5)
                all_answers.update(str(r) for r in answers)
            except dns.resolver.NoAnswer:
                continue  # Skip silently
            except dns.resolver.NXDOMAIN:
                all_answers.add("Domain does not exist")
                break  # Stop trying other resolvers
            except Exception as e:
                all_answers.add(f"Error from {server}: {e}")

        records[rtype] = list(all_answers) if all_answers else ["No records found"]

    return records


def save_dns_records_as_json(domain, records):
    """Save DNS records to a JSON file."""
    directory = extract_domain(domain)
    os.makedirs(directory, exist_ok=True)
    filename = os.path.join(directory, f"{directory}_DNSreords_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")


    data = {
        "domain": domain,
        "dns_records": records
    }



    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    print(f"\033[92mDNS records saved to {filename}\033[0m")


def DNS(target):
    # Clean domain if URL is passed
    if target.startswith("http://") or target.startswith("https://"):
        target = urlparse(target).netloc

    domain = target
    dns_records = get_dns_records(domain)
    save_dns_records_as_json(domain, dns_records)


# DNS('https://pixiv.net')