# import ssl
# import socket
# import idna
# import json
# from cryptography import x509
# from cryptography.hazmat.backends import default_backend
# from datetime import datetime
# from urllib.parse import urlparse
# import os


# def clean_domain(url_or_domain):
#     """Sanitize and extract domain from input."""
#     parsed = urlparse(url_or_domain)
#     if parsed.scheme:
#         return parsed.netloc
#     return url_or_domain


# def fetch_ssl_certificate(domain, port=443):
#     """Fetch raw SSL certificate for a domain."""
#     try:
#         ascii_domain = idna.encode(domain).decode("ascii")
#         ctx = ssl.create_default_context()

#         with socket.create_connection((ascii_domain, port), timeout=10) as sock:
#             with ctx.wrap_socket(sock, server_hostname=ascii_domain) as ssock:
#                 der_cert = ssock.getpeercert(binary_form=True)
#                 return der_cert

#     except Exception as e:
#         raise RuntimeError(f"Error connecting to {domain}: {str(e)}")


# def parse_ssl_certificate(cert_bytes):
#     """Parse DER-encoded certificate bytes."""
#     try:
#         x509_cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
#         now = datetime.utcnow()

#         # Try to extract SANs if present
#         try:
#             sans = [alt.value for alt in x509_cert.extensions.get_extension_for_class(
#                 x509.SubjectAlternativeName).value]
#         except x509.ExtensionNotFound:
#             sans = []

#         days_left = (x509_cert.not_valid_after - now).days

#         return {
#             "Issued_To": x509_cert.subject.rfc4514_string(),
#             "Issued_By": x509_cert.issuer.rfc4514_string(),
#             "Certificate_Valid_From": x509_cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S UTC'),
#             "Certificate_Expiry_Date": x509_cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S UTC'),
#             "Days_Until_Expiry": days_left,
#             "Serial_Number": hex(x509_cert.serial_number),
#             "Signature_Algorithm": x509_cert.signature_algorithm_oid._name,
#             "Supported_Domains_SAN": sans,
#         }

#     except Exception as e:
#         raise ValueError(f"Could not parse certificate: {str(e)}")


# def save_ssl_info(domain, info):
#     """Save the SSL certificate info to JSON file."""
#     folder_name = clean_domain(domain).replace(":", "_")
#     os.makedirs(folder_name, exist_ok=True)
#     timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
#     filename = os.path.join(folder_name, f"{folder_name}_SSL_TLS_{timestamp}.json")

#     with open(filename, "w", encoding="utf-8") as f:
#         json.dump(info, f, indent=4)

#     return filename


# def analyze_ssl_tls(target_url):
#     """Main runner to get SSL cert info and save it."""
#     domain = clean_domain(target_url)
#     result = {"Domain": domain}
#     try:
#         cert = fetch_ssl_certificate(domain)
#         result.update(parse_ssl_certificate(cert))
#     except Exception as e:
#         result["Error"] = str(e)

#     file_path = save_ssl_info(domain, result)
#     return file_path, result


# # Run example (will not actually connect since notebook is offline)
# # mock_target = "https://pixiv.net"
# # mock_path, mock_result = analyze_ssl_tls(mock_target)
# # print(mock_path, mock_result)



import ssl
import socket
import idna
import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from urllib.parse import urlparse
import os

def clean_domain(url_or_domain):
    """Sanitize and extract domain from input."""
    parsed = urlparse(url_or_domain)
    if parsed.scheme:
        return parsed.netloc
    return url_or_domain

def fetch_ssl_certificate(domain, port=443):
    """Fetch raw SSL certificate for a domain."""
    try:
        ascii_domain = idna.encode(domain).decode("ascii")
        ctx = ssl.create_default_context()
        
        with socket.create_connection((ascii_domain, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=ascii_domain) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                return der_cert
    
    except Exception as e:
        raise RuntimeError(f"Error connecting to {domain}: {str(e)}")

def parse_ssl_certificate(cert_bytes):
    """Parse DER-encoded certificate bytes."""
    try:
        x509_cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        now = datetime.utcnow()
        
        # Try to extract SANs if present
        try:
            sans = [alt.value for alt in x509_cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value]
        except x509.ExtensionNotFound:
            sans = []
        
        days_left = (x509_cert.not_valid_after - now).days
        
        return {
            "Issued_To": x509_cert.subject.rfc4514_string(),
            "Issued_By": x509_cert.issuer.rfc4514_string(),
            "Certificate_Valid_From": x509_cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S UTC'),
            "Certificate_Expiry_Date": x509_cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S UTC'),
            "Days_Until_Expiry": days_left,
            "Serial_Number": hex(x509_cert.serial_number),
            "Signature_Algorithm": x509_cert.signature_algorithm_oid._name,
            "Supported_Domains_SAN": sans,
        }
    
    except Exception as e:
        raise ValueError(f"Could not parse certificate: {str(e)}")

def save_ssl_info(domain, info):
    """Save the SSL certificate info to JSON file."""
    folder_name = clean_domain(domain).replace(":", "_")
    os.makedirs(folder_name, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(folder_name, f"{folder_name}_SSL_TLS_{timestamp}.json")
    
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(info, f, indent=4)
    
    return filename

def analyze_ssl_tls(target_url):
    """Main runner to get SSL cert info and save it."""
    domain = clean_domain(target_url)
    result = {"Domain": domain}
    
    try:
        cert = fetch_ssl_certificate(domain)
        result.update(parse_ssl_certificate(cert))
        
        # Save to file
        file_path = save_ssl_info(domain, result)
        result["file_path"] = file_path
        print(f"SSL/TLS info saved to {file_path}")
        
        # Return only the dictionary
        return result
        
    except Exception as e:
        # Return error as part of the dictionary
        result["Error"] = str(e)
        print(f"Error analyzing SSL/TLS for {domain}: {str(e)}")
        
        # Try to save even with error
        try:
            file_path = save_ssl_info(domain, result)
            result["file_path"] = file_path
            print(f"Error info saved to {file_path}")
        except Exception as save_error:
            result["save_error"] = str(save_error)
        
        # Return only the dictionary
        return result