'''
Incomplete Refer DNS.py
'''
import dns.resolver
import dns.query
import dns.zone
import dns.exception
import json
import socket
import os
from datetime import datetime
from urllib.parse import urlparse

def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or parsed.path


def get_nameservers(domain, resolvers=None):
    if resolvers is None:
        resolvers = ['8.8.8.8', '1.1.1.1']

    for resolver_ip in resolvers:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [resolver_ip]
            answers = resolver.resolve(domain, 'NS')
            return [str(rdata.target).rstrip('.') for rdata in answers]
        except Exception:
            continue
    return []

def resolve_ns_ip(ns):
    try:
        return socket.gethostbyname(ns)
    except socket.gaierror:
        return None

def try_zone_transfer(domain, ns):
    ns_ip = resolve_ns_ip(ns)
    if not ns_ip:
        return None

    try:
        xfr = dns.query.xfr(ns_ip, domain, timeout=5, lifetime=10)
        zone = dns.zone.from_xfr(xfr)
        return zone
    except (dns.exception.FormError, dns.exception.SyntaxError, dns.zone.NoSOA, dns.zone.NoNS, TimeoutError):
        return None
    except Exception:
        return None

def dump_zone_to_json(zone, domain):
    records = []
    for name, node in zone.nodes.items():
        for rdataset in node.rdatasets:
            for rdata in rdataset:
                records.append({
                    "name": f"{name}.{domain}",
                    "ttl": rdataset.ttl,
                    "type": dns.rdatatype.to_text(rdataset.rdtype),
                    "data": str(rdata)
                })
    return records

def run_zone_transfer_check(domain):
    print(f"[*] Looking up NS records for {domain}...")
    nameservers = get_nameservers(domain)

    if not nameservers:
        print("[!] No nameservers found.")
        return

    found_zones = []
    for ns in nameservers:
        print(f"[*] Trying zone transfer on {ns}...")
        zone = try_zone_transfer(domain, ns)
        if zone:
            print(f"[+] Zone transfer SUCCESS on {ns}")
            zone_data = {
                "nameserver": ns,
                "records": dump_zone_to_json(zone, domain)
            }
            found_zones.append(zone_data)
        else:
            print(f"[-] Zone transfer FAILED on {ns}")

    if found_zones:
        directory = extract_domain(domain)
        os.makedirs(directory, exist_ok=True)
        output_file = os.path.join(directory, f"{directory}_ZoneTransfer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

        with open(output_file, "w") as f:
            json.dump({
                "domain": domain,
                "zone_transfers": found_zones
            }, f, indent=4)
        print(f"[+] Zone transfer data saved to {output_file}")
    else:
        print("[-] No zone transfers succeeded.")


def zone_tr(target):
    # Example function call for demonstration:
    run_zone_transfer_check(target)

# zone_tr('zonetransfer.me')
