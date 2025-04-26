from pathlib import Path
import subprocess
import json
from fastapi import HTTPException
from rich.console import Console
from rich.panel import Panel
from rich.progress import track

# Setup paths - Adjusted for your specific directory structure
# Go up from controller location (controllers/newScans/) to project root (helper/)
# PROJECT_DIR = Path(__file__).resolve().parent.parent.parent  # Goes from controllers/newScans/ to controllers/
# KATANA_PATH = PROJECT_DIR / "helper" / "newScans" / "JsParser" / "katana" / "katana.exe"
# SECRET_FINDER_PATH = PROJECT_DIR / "helper" / "newScans" / "JsParser" / "SecretFinder" / "SecretFinder.py"
# KATANA_OUTPUT = PROJECT_DIR / "helper" / "newScans" / "JsParser" / "katana.txt"
# JSON_OUTPUT = PROJECT_DIR / "helper" / "newScans" / "JsParser" / "secrets_output.json"

console = Console()

# PROJECT_DIR = Path(__file__).resolve().parent.parent  # Goes from controllers/newScans/ to controllers/
KATANA_PATH = r"helper\newScans\JSParser\katana\katana.exe"
SECRET_FINDER_PATH = r"helper\newScans\JSParser\SecretFinder\SecretFinder.py"
KATANA_OUTPUT = r"helper\newScans\JSParser\katana.txt"  # Now a file
JSON_OUTPUT = r"helper\newScans\JSParser\secrets_output.json"  # Now a file


class SecretScanner:
    @staticmethod
    def run_katana(url: str):
        console.print(f"[bold cyan] Running Katana on:[/bold cyan] {url}")
        command = [
            str(KATANA_PATH),
            "-silent",
            "-u", url,
            "-jc",
            "-em", "js",
            "-o", str(KATANA_OUTPUT)
        ]

        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in process.stdout:
                print(line, end="")

            process.wait()
            if process.returncode == 0:
                console.print("[green] Katana finished. JS URLs saved to katana.txt[/green]")
                return {"status": "success", "message": "Katana scan completed"}
            else:
                raise HTTPException(
                    status_code=500,
                    detail=f"Katana failed with code {process.returncode}"
                )
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Error running Katana: {str(e)}"
            )

    @staticmethod
    def read_js_urls() -> list:
        try:
            with open(KATANA_OUTPUT, "r") as f:
                urls = [line.strip() for line in f if line.strip().endswith(".js")]
            console.print(f"[bold magenta] Found {len(urls)} JavaScript URLs[/bold magenta]")
            return urls
        except Exception as e:
            raise HTTPException(
                status_code=404,
                detail=f"Error reading JS URLs: {str(e)}"
            )

    @staticmethod
    def run_secretfinder(js_url: str) -> dict:
        command = f'python "{SECRET_FINDER_PATH}" -i {js_url} -o cli'
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            output_lines = []
            for line in process.stdout:
                output_lines.append(line.strip())
            process.wait()
            return {
                "url": js_url,
                "secrets": "\n".join(output_lines) if output_lines else "No secrets found."
            }
        except Exception as e:
            return {
                "url": js_url,
                "error": str(e)
            }

    @staticmethod
    def save_to_json(data: list):
        try:
            with open(JSON_OUTPUT, "w") as f:
                json.dump(data, f, indent=2)
            console.print(f"[bold green] Results saved to:[/bold green] {JSON_OUTPUT}")
            return {"status": "success", "message": "Results saved to JSON"}
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Error saving to JSON: {str(e)}"
            )

    @staticmethod
    def display_results(results: list):
        console.print("\n[bold underline cyan] SecretFinder Analysis Summary[/bold underline cyan]\n")
        for entry in results:
            url = entry["url"]
            content = entry.get("secrets") or entry.get("error", "No output")
            console.print(Panel.fit(content, title=f"[green] {url}", border_style="magenta"))
        return results

    @staticmethod
    def scan_target(target_url: str):
        SecretScanner.run_katana(target_url)
        js_urls = SecretScanner.read_js_urls()
        if not js_urls:
            return {"status": "warning", "message": "No JS URLs found to scan"}

        results = []
        for url in track(js_urls, description="Scanning JS files with SecretFinder..."):
            result = SecretScanner.run_secretfinder(url)
            results.append(result)

        SecretScanner.display_results(results)
        SecretScanner.save_to_json(results)
        return results