# models/newScans/emailAuditModel.py
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
<<<<<<< HEAD
from datetime import datetime
=======
import dns.resolver
import dns.query
import dns.message
import dns.name
import dns.flags
from datetime import datetime
import json

RESOLVER_IPS = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]

# Embedded dataset for audit metadata
AUDIT_METADATA = {
    "SPF uses hard fail (-all)": {
        "class": "SPF",
        "description": "SPF should use '-all' to reject unauthorized senders.",
        "severity": "high"
    },
    "DKIM public key exists": {
        "class": "DKIM",
        "description": "DKIM must have a published public key for signature verification.",
        "severity": "high"
    },
    "DMARC policy is reject/quarantine": {
        "class": "DMARC",
        "description": "DMARC should be set to 'reject' or 'quarantine' to enforce policy.",
        "severity": "medium"
    },
    "DNSSEC is enabled": {
        "class": "DNS",
        "description": "DNSSEC adds integrity to DNS responses and prevents spoofing.",
        "severity": "medium"
    },
    "SPF includes too many DNS lookups": {
        "class": "SPF",
        "description": "SPF records should avoid exceeding 10 DNS lookups to prevent policy failure.",
        "severity": "medium"
    },
    "DKIM key length is at least 1024 bits": {
        "class": "DKIM",
        "description": "Use a DKIM key length of 1024 bits or greater for secure signing.",
        "severity": "medium"
    },
    "DMARC rua reporting is enabled": {
        "class": "DMARC",
        "description": "DMARC should include 'rua' tag for aggregate reporting.",
        "severity": "low"
    },
    "DMARC ruf forensic reporting is enabled": {
        "class": "DMARC",
        "description": "DMARC should include 'ruf' tag to receive detailed failure reports.",
        "severity": "low"
    },
    "DMARC alignment mode is strict": {
        "class": "DMARC",
        "description": "DMARC should use 'adkim=s' and 'aspf=s' for strict alignment.",
        "severity": "low"
    },
    "MX records are valid and reachable": {
        "class": "MX",
        "description": "MX records should be present and point to reachable mail servers.",
        "severity": "high"
    },
    "No wildcard SPF mechanism (+all)": {
        "class": "SPF",
        "description": "Avoid using '+all' in SPF, which allows all senders and is insecure.",
        "severity": "critical"
    }
}
>>>>>>> a2fde178356247913e1be4f9504c7f8ad597f496

class EmailSecurityRequest(BaseModel):
    domain: str = Field(..., description="Domain to scan for email security", example="example.com")
    dkim_selector: str = Field(default="default", description="DKIM selector to use", example="default")
    userId: str

class RecordTagDetail(BaseModel):
    value: str
    name: str
    description: str

class ParsedRecord(BaseModel):
    raw: str
    parsed: Dict[str, RecordTagDetail]

class EmailSecurityResponse(BaseModel):
    domain: str
    SPF: Optional[ParsedRecord]
    DKIM: Optional[ParsedRecord]
    DMARC: Optional[ParsedRecord]
    MX: List[str]
    DNSSEC: str
<<<<<<< HEAD
    AuditSummary: Dict[str, str]
    created_time: datetime = Field(default_factory=datetime.utcnow)
    scanStatus: str = "success"

=======
    AuditSummary: Dict[str, Dict[str, str]]
>>>>>>> a2fde178356247913e1be4f9504c7f8ad597f496

class EmailSecurityModel:
    def __init__(self, domain, selector='default'):
        self.domain = domain
        self.selector = selector
        self.results = {}

    def run_all_checks(self):
        self.results = {
            "domain": self.domain,
            "SPF": self.fetch_spf(),
            "DKIM": self.fetch_dkim(self.selector),
            "DMARC": self.fetch_dmarc(),
            "MX": self.fetch_mx_records(),
            "DNSSEC": self.check_dnssec()
        }
        self.results["AuditSummary"] = self.validate_security()
        return self.results

    def resolve_with_fallback(self, domain, rdtype):
        for ns in RESOLVER_IPS:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ns]
            try:
                return resolver.resolve(domain, rdtype)
            except Exception:
                continue
        raise dns.resolver.NoAnswer(f"All resolvers failed to get {rdtype} record for {domain}")

    def fetch_spf(self):
        try:
            txt_records = self.resolve_with_fallback(self.domain, 'TXT')
            for rdata in txt_records:
                for txt_string in rdata.strings:
                    if b"v=spf1" in txt_string:
                        record = txt_string.decode()
                        return {
                            "raw": record,
                            "parsed": self.parse_spf_record(record)
                        }
            return {"raw": "No SPF record found.", "parsed": {}}
        except Exception as e:
            return {"raw": f"Error fetching SPF: {e}", "parsed": {}}

    def fetch_dkim(self, selector):
        try:
            dkim_domain = f"{selector}._domainkey.{self.domain}"
            txt_records = self.resolve_with_fallback(dkim_domain, 'TXT')
            record = ' '.join([r.to_text().strip('"') for r in txt_records])
            return {
                "raw": record,
                "parsed": self.parse_dkim_record(record)
            }
        except Exception as e:
            return {"raw": f"DKIM check failed: {e}", "parsed": {}}

    def fetch_dmarc(self):
        try:
            dmarc_domain = f"_dmarc.{self.domain}"
            txt_records = self.resolve_with_fallback(dmarc_domain, 'TXT')
            raw = ' '.join([r.to_text().strip('"') for r in txt_records])
            parsed = self.parse_dmarc_record(raw)
            return {
                "raw": raw,
                "parsed": parsed
            }
        except Exception as e:
            return {"raw": f"DMARC check failed: {e}", "parsed": {}}

    def fetch_mx_records(self):
        try:
            mx_records = self.resolve_with_fallback(self.domain, 'MX')
            return [f"{r.exchange} (Priority: {r.preference})" for r in mx_records]
        except Exception as e:
            return [f"MX check failed: {e}"]

    def check_dnssec(self):
        try:
            n = dns.name.from_text(self.domain)
            for ns in RESOLVER_IPS:
                query = dns.message.make_query(n, dns.rdatatype.DNSKEY, want_dnssec=True)
                try:
                    response = dns.query.udp(query, ns, timeout=2)
                    if response.flags & dns.flags.AD:
                        return "DNSSEC is enabled (AD flag set)."
                    elif response.answer:
                        return "DNSSEC records present but AD flag not validated."
                except Exception:
                    continue
            return "DNSSEC not configured."
        except Exception as e:
            return f"DNSSEC check failed: {e}"

    def validate_security(self):
        validation = {}
        for check, meta in AUDIT_METADATA.items():
            cls = meta["class"]
            severity = meta["severity"]
            status = "Fail"

            if cls == "SPF" and check in self.results.get("SPF", {}).get("parsed", {}):
                status = "Pass"
            elif cls == "DKIM" and check in self.results.get("DKIM", {}).get("parsed", {}):
                status = "Pass"
            elif cls == "DMARC" and check in self.results.get("DMARC", {}).get("parsed", {}):
                status = "Pass"
            elif cls == "DNS" and "enabled" in self.results.get("DNSSEC", "").lower():
                status = "Pass"
            elif cls == "MX" and "MX check failed" not in self.results.get("MX", [])[0]:
                status = "Pass"

            validation[check] = {
                "status": status,
                "class": cls,
                "severity": severity,
                "description": meta["description"]
            }

        return validation

    def export_json(self, filename=None):
        if not filename:
            filename = f"{self.domain}_email_security_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=4)
        return filename

    @staticmethod
    def parse_dmarc_record(record):
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

    @staticmethod
    def parse_spf_record(record):
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

    @staticmethod
    def parse_dkim_record(record):
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
