import requests
from config import SQLMAP_API_PORT, LOGGER

def sqlmap_api_request(endpoint, data=None, method='GET'):
    """
    Helper function to make requests to SQLMap API
    
    Args:
        endpoint (str): API endpoint
        data (dict, optional): Data to send in request
        method (str, optional): HTTP method (GET or POST)
        
    Returns:
        dict: Response from SQLMap API
    """
    url = f"http://127.0.0.1:{SQLMAP_API_PORT}/{endpoint}"
    
    try:
        if method == 'GET':
            response = requests.get(url)
        else:  # POST
            response = requests.post(url, json=data)
        
        return response.json()
    except Exception as e:
        LOGGER.error(f"Error communicating with SQLMap API: {str(e)}")
        return {"error": str(e)}