import subprocess
import time
from config import SQLMAP_PATH, LOGGER

class SQLMapService:
    """Service to manage SQLMap API server"""
    
    @staticmethod
    def start_sqlmap_api():
        """
        Start SQLMap API server as a background process
        
        Returns:
            subprocess.Popen: Process object for the SQLMap API server
        """
        try:
            # Run sqlmap with API flag
            cmd = ['python', SQLMAP_PATH, '-s']
            LOGGER.info(f"Starting SQLMap API with command: {' '.join(cmd)}")
            
            # Run in background
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
            
            # Wait for API to start
            time.sleep(5)
            LOGGER.info("SQLMap API server started successfully")
            return process
        except Exception as e:
            LOGGER.error(f"Failed to start SQLMap API: {str(e)}")
            return None