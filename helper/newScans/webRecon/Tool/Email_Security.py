import argparse
import os
import json
import dns.resolver
import dns.query
import dns.message
import dns.name
import dns.flags
from rich.console import Console
from rich.table import Table
from datetime import datetime

from urllib.parse import urlparse

def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or parsed.path


console = Console()


# ========== DMARC Parser ==========
def parse_dmarc_record(record: str) -> dict:
    tag_descriptions = {
        "v": ("Version", "Identifies the record as a DMARC record. Must be 'DMARC1'."),
        "p": ("Policy", "Policy for messages failing DMARC: 'none', 'quarantine', or 'reject'."),
        "rua": ("Aggregate Report URIs", "Where DMARC aggregate reports should be sent."),
        "ruf": ("Forensic Report URIs", "Where detailed failure reports are sent."),
        "fo": ("Failure Reporting Options", "When to generate forensic reports (0, 1, d, s)."),
        "pct": ("Percentage", "Percentage of messages subjected to filtering."),
        "aspf": ("SPF Alignment Mode", "Specifies alignment mode for SPF."),
        "adkim": ("DKIM Alignment Mode", "Specifies alignment mode for DKIM."),
    }

    result = {}
    tags = [item.strip() for item in record.split(';') if item]
    for tag in tags:
        if '=' not in tag:
            continue
        key, val = tag.split('=', 1)
        desc, longdesc = tag_descriptions.get(key.strip(), ("Unknown", "No description available."))
        result[key.strip()] = {
            "value": val.strip(),
            "name": desc,
            "description": longdesc
        }
    return result


# ========== SPF / DKIM Parser ==========
def parse_spf_record(record: str) -> dict:
    mechanisms = {
        "v": ("Version", "Specifies SPF version. Must be 'spf1'."),
        "ip4": ("IPv4", "Authorized IPv4 address to send mail."),
        "ip6": ("IPv6", "Authorized IPv6 address to send mail."),
        "include": ("Include", "Authorize domains whose SPF records should be included."),
        "a": ("A Record", "Match sender if their IP has A record for the domain."),
        "mx": ("MX Record", "Match sender if IP matches domain's MX records."),
        "exists": ("Exists", "Match if domain has valid DNS."),
        "all": ("All", "Catch-all mechanism; usually at end."),
        "-all": ("Fail", "Explicitly fail all others (hard fail)."),
        "~all": ("Soft Fail", "Mark others as soft fail."),
        "?all": ("Neutral", "No policy."),
        "+all": ("Pass All", "Pass all sources. Insecure."),
    }

    result = {}
    for segment in record.split():
        if '=' in segment:
            key, val = segment.split('=', 1)
        else:
            key, val = segment, ''
        desc, meaning = mechanisms.get(key.strip(), ("Unknown", "No description available."))
        result[key.strip()] = {
            "value": val.strip(),
            "name": desc,
            "description": meaning
        }
    return result


def parse_dkim_record(record: str) -> dict:
    tags = {
        "v": ("Version", "Must be DKIM1."),
        "k": ("Key Type", "Key type (rsa is common)."),
        "p": ("Public Key", "The public part of DKIM key used for signature verification."),
        "t": ("Flags", "Testing mode or other options."),
        "h": ("Hash Algorithms", "Hash algorithms allowed (e.g., sha256).")
    }

    result = {}
    segments = record.replace('"', '').split(';')
    for seg in segments:
        if '=' in seg:
            key, val = seg.strip().split('=', 1)
            desc, longdesc = tags.get(key.strip(), ("Unknown", "No description available."))
            result[key.strip()] = {
                "value": val.strip(),
                "name": desc,
                "description": longdesc
            }
    return result


# ========== DNS Fetchers ==========
def fetch_spf(domain):
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        for rdata in txt_records:
            for txt_string in rdata.strings:
                if b"v=spf1" in txt_string:
                    record = txt_string.decode()
                    return {
                        "raw": record,
                        "parsed": parse_spf_record(record)
                    }
        return {"raw": "No SPF record found.", "parsed": {}}
    except Exception as e:
        return {"raw": "No", "parsed": {}}


def fetch_dkim(domain, selector='default'):
    try:
        dkim_domain = f"{selector}._domainkey.{domain}"
        txt_records = dns.resolver.resolve(dkim_domain, 'TXT')
        record = ' '.join([r.to_text().strip('"') for r in txt_records])
        return {
            "raw": record,
            "parsed": parse_dkim_record(record)
        }
    except Exception as e:
        return {"raw": "No", "parsed": {}}


def fetch_dmarc(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        txt_records = dns.resolver.resolve(dmarc_domain, 'TXT')
        raw = ' '.join([r.to_text().strip('"') for r in txt_records])
        parsed = parse_dmarc_record(raw)
        return {
            "raw": raw,
            "parsed": parsed
        }
    except Exception as e:
        return {"raw": "No", "parsed": {}}


def fetch_mx_records(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return [f"{r.exchange} (Priority: {r.preference})" for r in mx_records]
    except Exception as e:
        return {"raw": "No"}


def check_dnssec(domain):
    try:
        n = dns.name.from_text(domain)
        ns = dns.resolver.get_default_resolver().nameservers[0]
        query = dns.message.make_query(n, dns.rdatatype.DNSKEY, want_dnssec=True)
        response = dns.query.udp(query, ns, timeout=2)

        if response.flags & dns.flags.AD:
            return "DNSSEC is enabled (AD flag set)."
        elif response.answer:
            return "DNSSEC records present but AD flag not validated."
        else:
            return "DNSSEC not configured."
    except Exception as e:
        return {"raw": "No"}


# ========== Output Display ==========
def print_parsed_block(console, record_name, record_data):
    table = Table(title=f"{record_name} Record Breakdown", show_lines=True)
    table.add_column("Tag", style="bold")
    table.add_column("TagValue", style="green")
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="magenta")

    for tag, details in record_data.items():
        table.add_row(tag, details["value"], details["name"], details["description"])

    console.print(table)


def print_results(domain, results):
    table = Table(title=f"Email Security Report for {domain}")
    table.add_column("Record", style="cyan", no_wrap=True)
    table.add_column("Details", style="magenta")

    for key, value in results.items():
        if isinstance(value, dict) and "raw" in value:
            table.add_row(f"{key} (Raw)", value["raw"])
        elif isinstance(value, list):
            table.add_row(key, "\n".join(value))
        else:
            table.add_row(key, value)
    console.print(table)

    if "SPF" in results and results["SPF"]["parsed"]:
        print_parsed_block(console, "SPF", results["SPF"]["parsed"])
    if "DKIM" in results and results["DKIM"]["parsed"]:
        print_parsed_block(console, "DKIM", results["DKIM"]["parsed"])
    if "DMARC" in results and results["DMARC"]["parsed"]:
        print_parsed_block(console, "DMARC", results["DMARC"]["parsed"])


# ========== JSON Export ==========
def export_json(domain, data):

    directory = domain
    os.makedirs(directory, exist_ok=True)


    filename = os.path.join(directory, f"{domain}_email_security_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"\n📁 Report saved to {filename}")


# ========== Main ==========
def email_sec(target):
    domain = extract_domain(target)
    print(f"\n🔍 Scanning domain: {domain}\n")

    results = {
        "SPF": fetch_spf(domain),
        "DKIM": fetch_dkim(domain),
        "DMARC": fetch_dmarc(domain),
        "MX": fetch_mx_records(domain),
        "DNSSEC": check_dnssec(domain)
    }

    print_results(domain, results)
    export_json(domain, results)


# if __name__ == "__main__":
# email_sec('https://pixiv.net')
