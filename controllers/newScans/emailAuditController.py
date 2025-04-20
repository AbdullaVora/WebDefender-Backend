# controllers/newScans/emailAuditController.py
from models.newScans.emailAuditModel import EmailSecurityModel
from datetime import datetime

class EmailSecurityController:
    """
    Controller for handling email security scanning requests
    """
    
    def check_email_security(self, domain: str, dkim_selector: str = "default"):
        """
        Run all email security checks for a domain
        
        Args:
            domain (str): The domain to scan
            dkim_selector (str): DKIM selector to use (default: "default")
            
        Returns:
            dict: Results of all security checks
        """
        model = EmailSecurityModel(domain, dkim_selector)
        results = model.run_all_checks()
        return results
    
    def export_results(self, domain: str, dkim_selector: str = "default"):
        """
        Export scan results to a JSON file
        
        Args:
            domain (str): The domain to scan
            dkim_selector (str): DKIM selector to use
            
        Returns:
            str: Filename of the exported JSON
        """
        model = EmailSecurityModel(domain, dkim_selector)
        model.run_all_checks()
        filename = model.export_json()
        return filename
    
    def get_summary(self, domain: str, dkim_selector: str = "default"):
        """
        Get only the security validation summary for a domain
        
        Args:
            domain (str): The domain to scan
            dkim_selector (str): DKIM selector to use
            
        Returns:
            dict: Security validation summary
        """
        model = EmailSecurityModel(domain, dkim_selector)
        model.run_all_checks()
        return {
            "domain": domain,
            "summary": model.results["AuditSummary"]
        }