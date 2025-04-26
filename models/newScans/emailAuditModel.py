# models/newScans/emailAuditModel.py
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
from datetime import datetime

# Request model
class EmailSecurityRequest(BaseModel):
    domain: str = Field(..., description="Domain to scan for email security", example="example.com")
    dkim_selector: str = Field(default="default", description="DKIM selector to use", example="default")
    userId: str
# Response models for parsed records
class RecordTagDetail(BaseModel):
    value: str
    name: str
    description: str

class ParsedRecord(BaseModel):
    raw: str
    parsed: Dict[str, RecordTagDetail]

# Main response model
class EmailSecurityResponse(BaseModel):
    domain: str
    SPF: Optional[ParsedRecord]
    DKIM: Optional[ParsedRecord]
    DMARC: Optional[ParsedRecord]
    MX: List[str]
    DNSSEC: str
    AuditSummary: Dict[str, str]
    created_time: datetime = Field(default_factory=datetime.utcnow)
    scanStatus: str = "success"


# Model for the underlying business logic
class EmailSecurityModel:
    def __init__(self, domain, selector='default'):
        self.domain = domain
        self.selector = selector
        self.results = {}

    def run_all_checks(self):
        """Run all email security checks for the domain"""
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

    def fetch_spf(self):
        """Fetch SPF record for the domain"""
        import dns.resolver
        try:
            txt_records = dns.resolver.resolve(self.domain, 'TXT')
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
        """Fetch DKIM record for the domain with given selector"""
        import dns.resolver
        try:
            dkim_domain = f"{selector}._domainkey.{self.domain}"
            txt_records = dns.resolver.resolve(dkim_domain, 'TXT')
            record = ' '.join([r.to_text().strip('"') for r in txt_records])
            return {
                "raw": record,
                "parsed": self.parse_dkim_record(record)
            }
        except Exception as e:
            return {"raw": f"DKIM check failed: {e}", "parsed": {}}

    def fetch_dmarc(self):
        """Fetch DMARC record for the domain"""
        import dns.resolver
        try:
            dmarc_domain = f"_dmarc.{self.domain}"
            txt_records = dns.resolver.resolve(dmarc_domain, 'TXT')
            raw = ' '.join([r.to_text().strip('"') for r in txt_records])
            parsed = self.parse_dmarc_record(raw)
            return {
                "raw": raw,
                "parsed": parsed
            }
        except Exception as e:
            return {"raw": f"DMARC check failed: {e}", "parsed": {}}

    def fetch_mx_records(self):
        """Fetch MX records for the domain"""
        import dns.resolver
        try:
            mx_records = dns.resolver.resolve(self.domain, 'MX')
            return [f"{r.exchange} (Priority: {r.preference})" for r in mx_records]
        except Exception as e:
            return [f"MX check failed: {e}"]

    def check_dnssec(self):
        """Check DNSSEC status for the domain"""
        import dns.resolver
        import dns.query
        import dns.message
        import dns.name
        import dns.flags
        try:
            n = dns.name.from_text(self.domain)
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
            return f"DNSSEC check failed: {e}"

    def validate_security(self):
        """Validate the security settings from results"""
        validation = {}

        spf = self.results.get("SPF", {}).get("parsed", {})
        spf_valid = any(tag in spf for tag in ['-all'])
        validation["SPF uses hard fail (-all)"] = "Pass" if spf_valid else "Fail"

        dkim = self.results.get("DKIM", {}).get("parsed", {})
        dkim_valid = 'p' in dkim and dkim['p']['value'] != ''
        validation["DKIM public key exists"] = "Pass" if dkim_valid else "Fail"

        dmarc = self.results.get("DMARC", {}).get("parsed", {})
        dmarc_policy = dmarc.get("p", {}).get("value", "none") if dmarc else None
        dmarc_valid = dmarc_policy in ['quarantine', 'reject'] if dmarc_policy else False
        validation["DMARC policy is reject/quarantine"] = "Pass" if dmarc_valid else "Fail"

        dnssec = self.results.get("DNSSEC", "")
        dnssec_valid = "enabled" in dnssec.lower()
        validation["DNSSEC is enabled"] = "Pass" if dnssec_valid else "Fail"

        return validation

    def export_json(self, filename=None):
        """Export results to a JSON file"""
        import json
        from datetime import datetime
        
        if not filename:
            filename = f"{self.domain}_email_security_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=4)
        
        return filename

    @staticmethod
    def parse_dmarc_record(record):
        """Parse a DMARC record into components"""
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
        """Parse an SPF record into components"""
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
        """Parse a DKIM record into components"""
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