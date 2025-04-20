from fastapi import HTTPException
from Wappalyzer import Wappalyzer, WebPage
from typing import Dict, Any, List
from models.newScans.TechnologiesModel import WappalyzerScanRequest, WappalyzerScanResponse, TechnologyInfo
import warnings

warnings.simplefilter("ignore")

class WappalyzerController:
    @staticmethod
    async def analyze_website(request: WappalyzerScanRequest) -> WappalyzerScanResponse:
        """
        Analyze a website using Wappalyzer
        """
        try:
            webpage = WebPage.new_from_url(request.url)
            wappalyzer = Wappalyzer.latest()
            technologies = wappalyzer.analyze_with_versions_and_categories(webpage)

            if not technologies:
                raise HTTPException(
                    status_code=404,
                    detail="No technologies detected"
                )

            categorized_tech = {}
            for tech, details in technologies.items():
                category = ", ".join(details.get("categories", ["Unknown"]))
                version = details.get("version", "N/A")

                if category not in categorized_tech:
                    categorized_tech[category] = []

                categorized_tech[category].append(
                    TechnologyInfo(
                        technology=tech,
                        version=version
                    )
                )

            return WappalyzerScanResponse(
                website=request.url,
                detected_technologies=categorized_tech
            )

        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Analysis failed: {str(e)}"
            )
    @staticmethod
    def get_scan_history() -> List[Dict[str, Any]]:
        """
        Returns empty list since we're not storing scans anymore
        Maintained for API compatibility
        """
        return []

    @staticmethod
    def get_scan_by_id(scan_id: int) -> Dict[str, Any]:
        """
        Returns error response since we're not storing scans
        Maintained for API compatibility
        """
        return {"error": "Scan storage is disabled"}