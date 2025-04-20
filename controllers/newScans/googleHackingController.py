import json
import os
from pathlib import Path
from typing import Dict, List, Tuple, Any

class DorkController:
    def __init__(self):
        self.dorks = self._load_dorks()

    def _get_dork_path(self) -> Path:
        """Get absolute path to dork.json"""
        current_dir = Path(__file__).parent  # controllers/newScans/
        project_root = current_dir.parent.parent  # WebDefender_API/
        return project_root / "helper" / "newScans" / "dork.json"

    def _load_dorks(self) -> Dict[str, List[str]]:
        """Load dorks from JSON file"""
        dork_path = self._get_dork_path()
        
        try:
            if not dork_path.exists():
                raise FileNotFoundError(f"Dork file not found at: {dork_path}")

            with open(dork_path, "r") as file:
                data = json.load(file)
                
            if "google_dorks" not in data:
                raise ValueError("Invalid dork file format: missing 'google_dorks' key")
                
            return {category["category"]: category["dorks"] for category in data["google_dorks"]}
            
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON format in dork file")
        except Exception as e:
            raise RuntimeError(f"Failed to load dorks: {str(e)}")

    def get_dork_categories(self) -> Dict[str, List[str]]:
        """Get available dork categories"""
        return {"categories": list(self.dorks.keys())}

    def perform_search(self, domain: str, dork_type: str) -> Tuple[Dict[str, Any], int]:
        """Perform search and return results"""
        if not domain or not dork_type:
            return {"status": "error", "message": "Domain and dork type are required"}, 400
            
        if dork_type not in self.dorks:
            return {"status": "error", "message": "Invalid dork type"}, 400

        queries = [dork.replace("{}", domain) for dork in self.dorks[dork_type]]
        search_urls = [f"https://www.google.com/search?q={query}" for query in queries]
        
        return {"status": "success", "urls": search_urls}, 200