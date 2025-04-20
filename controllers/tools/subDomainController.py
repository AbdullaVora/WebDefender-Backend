# import requests
# import threading
# import sublist3r
# import httpx
# import socket
# from config.database import db  # Make sure this correctly initializes MongoDB
# from models.report import subdomainReport
# import asyncio


# class SubdomainScanner:
#     def __init__(self, domain):
#         """Initialize the scanner with the target domain."""
#         self.domain = domain.strip()
#         self.HEADERS = {'User-Agent': 'Mozilla/5.0'}
#         self.found_subdomains = set()
#         self.live_subdomains = {}
#         self.lock = threading.Lock()

#     def fetch_subdomains_crtsh(self):
#         """Fetches subdomains from crt.sh (Certificate Transparency Logs)"""
#         print(f"[*] Searching crt.sh for subdomains of {self.domain}...")
#         url = f"https://crt.sh/?q=%25.{self.domain}&output=json"

#         try:
#             response = requests.get(url, headers=self.HEADERS, timeout=15)
#             if response.status_code == 200:
#                 data = response.json()
#                 subdomains = {entry['name_value'].strip() for entry in data}
#                 self.process_subdomains(subdomains, "crt.sh")
#         except Exception as e:
#             print(f"[-] crt.sh error: {e}")

#     def fetch_subdomains_otx(self):
#         """Fetches subdomains from AlienVault OTX"""
#         print(f"[*] Searching AlienVault OTX for subdomains of {self.domain}...")
#         url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"

#         try:
#             response = requests.get(url, headers=self.HEADERS, timeout=10)
#             if response.status_code == 200:
#                 data = response.json()
#                 subdomains = {entry['hostname'].strip() for entry in data.get('passive_dns', [])}
#                 self.process_subdomains(subdomains, "AlienVault OTX")
#         except Exception as e:
#             print(f"[-] AlienVault OTX error: {e}")

#     def fetch_subdomains_sublist3r(self):
#         """Fetches subdomains using Sublist3r"""
#         print(f"[*] Searching Sublist3r for subdomains of {self.domain}...")
#         try:
#             subdomains = sublist3r.main(
#                 self.domain,
#                 40,
#                 savefile=False,
#                 silent=True,
#                 verbose=False,
#                 engines=None,
#                 ports=None,  # Added missing argument
#                 enable_bruteforce=False  # Added missing argument
#             )
#             self.process_subdomains(subdomains, "Sublist3r")
#         except TypeError as e:
#             print(f"[-] Sublist3r error: {e}")
#         except Exception as e:
#             print(f"[-] Unexpected error in Sublist3r: {e}")

#     def process_subdomains(self, subdomains, source):
#         """Processes, filters, and prints unique subdomains"""
#         with self.lock:
#             for sub in subdomains:
#                 if sub and sub not in self.found_subdomains and not sub.startswith("-") and not sub.isdigit():
#                     self.found_subdomains.add(sub)
#                     print(f"[+] {sub}  ({source})")

#     def check_live_subdomains(self):
#         """Checks which subdomains are live using httpx."""
#         print("\n[*] Checking live subdomains...")

#         def check_subdomain(sub):
#             urls = [f"http://{sub}", f"https://{sub}"]
#             for url in urls:
#                 try:
#                     response = httpx.get(url, headers=self.HEADERS, timeout=5, follow_redirects=False)
#                     if response.status_code in {200, 201, 202, 204, 301, 302, 403, 405}:
#                         with self.lock:
#                             self.live_subdomains[sub] = None
#                             print(f"[✔] LIVE: {sub} ({url}) [{response.status_code}]")
#                         break
#                 except httpx.RequestError:
#                     continue

#         threads = [threading.Thread(target=check_subdomain, args=(sub,)) for sub in self.found_subdomains]
#         for t in threads:
#             t.start()
#         for t in threads:
#             t.join()

#         print(f"\n[*] Live subdomains found: {len(self.live_subdomains)}")

#     def resolve_ips(self):
#         """Resolves IP addresses for live subdomains"""
#         print("\n[*] Resolving IP addresses for live subdomains...")

#         def resolve_ip(sub):
#             try:
#                 ip = socket.gethostbyname(sub)
#                 with self.lock:
#                     self.live_subdomains[sub] = ip
#                     print(f"[IP] {sub} -> {ip}")
#             except socket.gaierror:
#                 pass

#         threads = [threading.Thread(target=resolve_ip, args=(sub,)) for sub in self.live_subdomains]
#         for t in threads:
#             t.start()
#         for t in threads:
#             t.join()

#     async def save_results(self):
#         """Saves subdomains, live subdomains, and their IPs to files"""
#         with open(f"{self.domain}_subdomains.txt", "w") as f:
#             for sub in sorted(self.found_subdomains):
#                 f.write(sub + "\n")

#         with open(f"{self.domain}_live_subdomains.txt", "w") as f:
#             for sub in sorted(self.live_subdomains.keys()):
#                 f.write(sub + "\n")

#         with open(f"{self.domain}_live_subdomains_with_ip.txt", "w") as f:
#             for sub, ip in sorted(self.live_subdomains.items()):
#                 if ip:
#                     f.write(f"{sub} -> {ip}\n")

#         print(f"\n[*] Subdomains saved to {self.domain}_subdomains.txt")
#         print(f"[*] Live subdomains saved to {self.domain}_live_subdomains.txt")
#         print(f"[*] Live subdomains with IPs saved to {self.domain}_live_subdomains_with_ip.txt")

#         # ✅ Store in MongoDB
#         if db is None:
#             print("Error: Database connection is missing!")
#             return

#         subdomain_data = subdomainReport(
#             domain=self.domain,
#             subdomains=sorted(self.found_subdomains),
#             live_subdomains=[{"subdomain": sub, "ip": ip or "N/A"} for sub, ip in self.live_subdomains.items()]
#         ).dict()

#         try:
#             result = await db.subdomain_reports.insert_one(subdomain_data)  # Store in 'subdomain_reports' collection
#             print(f"Successfully stored in MongoDB. ID: {result.inserted_id}")
#         except Exception as e:
#             print(f"Error saving to MongoDB: {e}")

#     def run_scan(self):
#         """Runs the full subdomain enumeration process"""
#         print(f"[*] Starting subdomain scan for {self.domain}...")

#         # Start subdomain enumeration threads
#         threads = [
#             threading.Thread(target=self.fetch_subdomains_crtsh),
#             threading.Thread(target=self.fetch_subdomains_otx),
#             threading.Thread(target=self.fetch_subdomains_sublist3r)
#         ]
#         for t in threads:
#             t.start()
#         for t in threads:
#             t.join()

#         print(f"\n[*] Subdomain enumeration completed. Found {len(self.found_subdomains)} unique subdomains.")

#         self.check_live_subdomains()
#         self.resolve_ips()

#         loop = asyncio.get_event_loop()
#         loop.create_task(self.save_results())  # Schedule the async function



import requests
import threading
import sublist3r
import httpx
import socket
import asyncio
from datetime import datetime
from config.database import db  # Ensure correct MongoDB initialization
from models.report import subdomainReport
from fastapi.encoders import jsonable_encoder

class SubdomainScanner:
    def __init__(self, domain):
        self.domain = domain.strip()
        self.HEADERS = {'User-Agent': 'Mozilla/5.0'}
        self.found_subdomains = set()
        self.live_subdomains = {}
        self.logs = []
        self.lock = threading.Lock()

    def log_scan_event(self, event, details=None):
        """Logs scanning events within the report with detailed information."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": event,
            "details": str(details) if details is not None else "No details provided"
        }
        self.logs.append(log_entry)
        print(f"[LOG] {event}: {log_entry['details']}")

    def fetch_subdomains_crtsh(self):
        print(f"[*] Searching crt.sh for subdomains of {self.domain}...")
        self.log_scan_event("Fetching from crt.sh")
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        try:
            response = requests.get(url, headers=self.HEADERS, timeout=15)
            if response.status_code == 200:
                data = response.json()
                subdomains = {entry['name_value'].strip() for entry in data}
                self.process_subdomains(subdomains, "crt.sh")
        except Exception as e:
            print(f"[-] crt.sh error: {e}")
            self.log_scan_event("Error", str(e))

    def fetch_subdomains_otx(self):
        print(f"[*] Searching AlienVault OTX for subdomains of {self.domain}...")
        self.log_scan_event("Fetching from AlienVault OTX")
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        try:
            response = requests.get(url, headers=self.HEADERS, timeout=10)
            if response.status_code == 200:
                data = response.json()
                subdomains = {entry['hostname'].strip() for entry in data.get('passive_dns', [])}
                self.process_subdomains(subdomains, "AlienVault OTX")
        except Exception as e:
            print(f"[-] AlienVault OTX error: {e}")
            self.log_scan_event("Error", str(e))

    def fetch_subdomains_sublist3r(self):
        print(f"[*] Searching Sublist3r for subdomains of {self.domain}...")
        self.log_scan_event("Fetching from Sublist3r")
        try:
            subdomains = sublist3r.main(
                self.domain, 40, savefile=False, silent=True, verbose=False,
                engines=None, ports=None, enable_bruteforce=False
            )
            self.process_subdomains(subdomains, "Sublist3r")
        except Exception as e:
            print(f"[-] Sublist3r error: {e}")
            self.log_scan_event("Error", str(e))

    def process_subdomains(self, subdomains, source):
        with self.lock:
            for sub in subdomains:
                if sub and sub not in self.found_subdomains:
                    self.found_subdomains.add(sub)
                    print(f"[+] {sub}  ({source})")

    def check_live_subdomains(self):
        print("\n[*] Checking live subdomains...")
        self.log_scan_event("Checking live subdomains")

        def check_subdomain(sub):
            for url in [f"http://{sub}", f"https://{sub}"]:
                try:
                    response = httpx.get(url, headers=self.HEADERS, timeout=5)
                    if response.status_code in {200, 301, 302, 403}:
                        with self.lock:
                            self.live_subdomains[sub] = None
                            print(f"[✔] LIVE: {sub} ({url}) [{response.status_code}]")
                        break
                except httpx.RequestError:
                    continue

        threads = [threading.Thread(target=check_subdomain, args=(sub,)) for sub in self.found_subdomains]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def resolve_ips(self):
        print("\n[*] Resolving IP addresses...")
        self.log_scan_event("Resolving IPs")

        def resolve_ip(sub):
            try:
                ip = socket.gethostbyname(sub)
                with self.lock:
                    self.live_subdomains[sub] = ip
                    print(f"[IP] {sub} -> {ip}")
            except socket.gaierror:
                pass

        threads = [threading.Thread(target=resolve_ip, args=(sub,)) for sub in self.live_subdomains]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    async def save_results(self):
        print(f"[*] Saving scan results")
        self.log_scan_event("Saving scan results")

        subdomain_data = {
            "domain": self.domain,
            "subdomains": sorted(self.found_subdomains),
            "live_subdomains": [{"subdomain": sub, "ip": ip or "N/A"} for sub, ip in self.live_subdomains.items()],
            "logs": self.logs,
            "timestamp": datetime.utcnow()
        }

        return jsonable_encoder(subdomain_data)  # ✅ Ensures JSON serialization


    # def run_scan(self):
    #     print(f"[*] Starting scan for {self.domain}...")
    #     self.log_scan_event("Scan started")

    #     threads = [
    #         threading.Thread(target=self.fetch_subdomains_crtsh),
    #         threading.Thread(target=self.fetch_subdomains_otx),
    #         threading.Thread(target=self.fetch_subdomains_sublist3r)
    #     ]
    #     for t in threads:
    #         t.start()
    #     for t in threads:
    #         t.join()

    #     self.check_live_subdomains()
    #     self.resolve_ips()
    #     loop = asyncio.get_event_loop()
    #     loop.create_task(self.save_results())
    #     self.log_scan_event("Scan completed")

    # async def run_scan(self):
    #     print(f"[*] Starting scan for {self.domain}...")
    #     self.log_scan_event("Scan started")

    #     # Run subdomain fetching concurrently
    #     await asyncio.gather(
    #         asyncio.to_thread(self.fetch_subdomains_crtsh),
    #         asyncio.to_thread(self.fetch_subdomains_otx),
    #         asyncio.to_thread(self.fetch_subdomains_sublist3r)
    #     )

    #     # Checking live subdomains and resolving IPs (not async, so run sequentially)
    #     self.check_live_subdomains()
    #     self.resolve_ips()

    #     self.log_scan_event("Scan completed")

    #     # Ensure results are saved before returning
    #     scan_results = await self.save_results()
    #     return scan_results

    async def run_scan(self, payloads=None):
        print(f"[*] Starting scan for {self.domain}...")

        if payloads:
            print(f"[*] Received payloads: {payloads}")
            self.log_scan_event("Received payloads", payloads)

        self.log_scan_event("Scan started")

        # Run subdomain fetching concurrently
        await asyncio.gather(
            asyncio.to_thread(self.fetch_subdomains_crtsh),
            asyncio.to_thread(self.fetch_subdomains_otx),
            asyncio.to_thread(self.fetch_subdomains_sublist3r)
        )

        # Checking live subdomains and resolving IPs (not async, so run sequentially)
        self.check_live_subdomains()
        self.resolve_ips()

        self.log_scan_event("Scan completed")

        # Ensure results are saved before returning
        scan_results = await self.save_results()
        return scan_results
