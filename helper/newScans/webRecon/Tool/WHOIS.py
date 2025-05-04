# import whois
# import json
# import os
# from datetime import datetime
# from urllib.parse import urlparse

# def extract_domain(url):
#     parsed = urlparse(url)
#     return parsed.netloc or parsed.path

# def run_whois(query):
#     w = whois.whois(query)
#     return w.text

# def whois_res(target):
#     # Example input; replace or extend with a list if needed
#     user_input = target

#     # Run lookup
#     raw_output = run_whois(user_input)

#     # Save in JSON
#     output_data = {user_input: raw_output}
#     directory = extract_domain(target)
#     os.makedirs(directory, exist_ok=True)
#     filename = os.path.join(directory, f"{directory}_Whois_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

#     with open(filename, "w") as f:
#         json.dump(output_data, f, indent=2)

#     print(f"WHOIS info saved to {filename}")


# # whois_res('pixiv.net')


import whois
import json
import os
from datetime import datetime
from urllib.parse import urlparse

def extract_domain(url):
    """Extract domain from URL"""
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    # Remove www. prefix if present
    if domain.startswith('www.'):
        domain = domain[4:]
    # Remove port if present
    domain = domain.split(':')[0]
    return domain

def run_whois(query):
    """Run WHOIS query with error handling"""
    try:
        # Try the imported whois module
        result = whois.whois(query)
        # Check if the result has 'text' attribute
        if hasattr(result, 'text'):
            return result.text
        # Some whois packages return a dictionary directly
        elif isinstance(result, dict) and 'text' in result:
            return result['text']
        # Some versions return an object with __str__ method
        else:
            return str(result)
    except AttributeError:
        # If whois.whois doesn't exist, try alternative approaches
        try:
            # Try using query method instead
            result = whois.query(query)
            return str(result)
        except Exception as e:
            return f"WHOIS lookup failed: {str(e)}"
    except Exception as e:
        return f"WHOIS lookup failed: {str(e)}"

def whois_res(target):
    """Main function for WHOIS lookup that returns a dictionary result"""
    try:
        # Clean the input to get domain
        domain = extract_domain(target)
        
        # Run lookup
        raw_output = run_whois(domain)
        
        # Create result dictionary
        result = {
            "domain": domain,
            "whois_data": raw_output
        }
        
        # Save in JSON
        try:
            directory = domain
            os.makedirs(directory, exist_ok=True)
            filename = os.path.join(directory, f"{domain}_Whois_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            
            output_data = {domain: raw_output}
            with open(filename, "w") as f:
                json.dump(output_data, f, indent=2)
                
            print(f"WHOIS info saved to {filename}")
            result["file_path"] = filename
        except Exception as save_error:
            result["save_error"] = str(save_error)
        
        # Always return a dictionary
        return result
        
    except Exception as e:
        # Return error as dictionary
        return {
            "error": f"WHOIS lookup failed: {str(e)}"
        }