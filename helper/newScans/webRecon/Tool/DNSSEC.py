'''
Complete
'''
import whois
from datetime import datetime
import dns.resolver
import json
import os
from urllib.parse import urlparse

def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or parsed.path


def fetch_whois_info(domain):
    try:
        w = whois.whois(domain)

        def check_dns_record(domain, record_type):
            """Check if a DNS record exists for the given domain."""
            try:
                dns.resolver.resolve(domain, record_type)
                return True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                return False

        whois_info = {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date) if w.creation_date else "N/A",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "N/A",
            "status": w.status if w.status else "N/A",
            "name_servers": w.name_servers if w.name_servers else "N/A",
            "dns_records": {
                "DNSKEY": check_dns_record(domain, 'DNSKEY'),
                "DS": check_dns_record(domain, 'DS'),
                "RRSIG": check_dns_record(domain, 'RRSIG')
            }
        }
        return whois_info
    except Exception as e:
        print("Error fetching Whois information:", str(e))
        return None

def save_whois_info_as_json(domain):
    directory = extract_domain(domain)
    os.makedirs(directory, exist_ok=True)
    filename = os.path.join(directory, f"{directory}_DNSSEC_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

    whois_info = fetch_whois_info(domain)
    if whois_info:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(whois_info, f, indent=4, ensure_ascii=False)
        print(f"\033[92mWhois information saved to {filename}\033[0m")
    else:
        print("\033[91mFailed to retrieve Whois information.\033[0m")

def dnssec(target):
    # Example usage
    domain = target #"pixiv.net"
    save_whois_info_as_json(domain)
# dnssec('https://pixiv.net')