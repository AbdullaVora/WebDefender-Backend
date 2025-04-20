from fastapi import HTTPException
import whois
import json
import datetime
from typing import Dict, Optional

class WhoisController:
    @staticmethod
    def fetch_whois_info(domain: str) -> Dict:
        """Fetch WHOIS information for a given domain."""
        try:
            w = whois.whois(domain)
            whois_dict = dict(w)

            # Normalize and sanitize WHOIS data
            for key, value in whois_dict.items():
                if isinstance(value, list):
                    if key in ("creation_date", "updated_date", "expiration_date"):
                        value = next((v for v in value if isinstance(v, datetime.datetime)), None)
                        whois_dict[key] = value.isoformat() if value else "N/A"
                    else:
                        whois_dict[key] = ", ".join(str(v).strip() for v in value if v)
                elif isinstance(value, dict):
                    whois_dict[key] = json.dumps(value)
                elif isinstance(value, datetime.datetime):
                    whois_dict[key] = value.isoformat()
                elif value is None:
                    whois_dict[key] = "N/A"

            # Fallbacks
            whois_dict.setdefault("name", whois_dict.get("registrant_name", "N/A"))
            whois_dict.setdefault("org", whois_dict.get("registrant_org", "N/A"))
            whois_dict.setdefault("registrar_url", whois_dict.get("url", "N/A"))
            whois_dict.setdefault("emails", "N/A")
            whois_dict.setdefault("dnssec", "N/A")

            if "name_servers" in whois_dict:
                whois_dict["name_servers"] = ", ".join(
                    ns.strip().rstrip(".") for ns in whois_dict["name_servers"].split(",")
                )

            hosting_provider = whois_dict.get("org") or whois_dict.get("registrar") or "Unknown"
            whois_dict["hosting_provider"] = hosting_provider

            # Add timestamp
            whois_dict["timestamp"] = datetime.datetime.now().isoformat()

            return whois_dict

        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Could not fetch WHOIS data for {domain}: {str(e)}")

    @staticmethod
    def save_whois_to_json(whois_data: Dict, filename: str = "whois_info.json") -> Dict:
        """Save WHOIS data to JSON file."""
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(whois_data, f, indent=4, ensure_ascii=False)
            return {"status": "success", "filename": filename, "message": "WHOIS data saved successfully"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to save WHOIS data: {str(e)}")