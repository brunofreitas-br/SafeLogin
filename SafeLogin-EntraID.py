import azure.functions as func
import logging
import requests
from urllib.parse import urlparse
from datetime import datetime
import hashlib
import hmac
import base64
import json
import socket
import os

# Log Analytics (Sentinel) Details
customer_id = os.environ.get('LOG_ANALYTICS_WORKSPACE_ID')
shared_key = os.environ.get('LOG_ANALYTICS_SHARED_KEY')
log_type = 'SafeLoginDetections'

# Alert Image URL Details
image_url = os.environ.get('IMAGE_URL')

# Function to Build the Authorization Signature for Sentinel API
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = f"SharedKey {customer_id}:{encoded_hash}"
    return authorization

# Function to Send Data to Sentinel
def send_data_to_sentinel(logs):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    body = json.dumps(logs)
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = f"https://{customer_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"
    
    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }
    
    response = requests.post(uri, data=body, headers=headers)
    if response.status_code >= 200 and response.status_code <= 299:
        logging.info(f"Data sent to Sentinel successfully. Response code: {response.status_code}")
    else:
        logging.error(f"Failed to send data to Sentinel. Response code: {response.status_code}")

# Function to resolve IP from a URL
def resolve_ip_from_url(url):
    try:
        hostname = urlparse(url).hostname
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        logging.error(f"Could not resolve IP for URL {url}: {e}")
        return None

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="safelogin_trigger")
def safelogin_trigger(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processing a request.')

    # Captures the client IP of the request
    client_ip = req.headers.get('X-Forwarded-For') or req.headers.get('X-Original-For')
    
    if not client_ip:
        client_ip = req.remote_addr

    logging.info(f"Client IP: {client_ip}")

    # Get the Referer URL to check for phishing
    referer_url = req.headers.get('Referer')

    # Legitimate URLs for Validation
    valid_urls = [
        f"https://login.microsoftonline.com/"
    ]

    if referer_url:
        # Extract the Base URL for Comparison
        parsed_url = urlparse(referer_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

        logging.info(f"Referer URL: {referer_url}")
        logging.info(f"Base URL: {base_url}")

        if base_url in valid_urls:
            # If the URL is legitimate, return status 204 (No Content)
            return func.HttpResponse(status_code=204)
        else:
            # Resolve IP of the suspected phishing URL
            malicious_ip = resolve_ip_from_url(referer_url)

            # If the URL is not legitimate, send a phishing alert image
            image_response = requests.get(image_url)

            if image_response.status_code == 200:
                
                # Log the phishing attempt to Sentinel
                phishing_log = [{
                    "Time": datetime.utcnow().isoformat(),
                    "SuspectURL": referer_url,
                    "ClientIP": client_ip,
                    "MaliciousIP": malicious_ip,
                    "ThreatType": "Phishing Attempt - Suspicious URL"
                }]
                
                # Send the data to Sentinel
                send_data_to_sentinel(phishing_log)

                # Return the phishing alert image
                return func.HttpResponse(image_response.content, mimetype="image/png", status_code=200)
            else:
                logging.error(f"Error loading phishing alert image. URL Referer: {referer_url}")
                return func.HttpResponse("Error loading phishing alert image.", status_code=500)
    else:
        logging.error("Referer URL not provided or is empty.")
        return func.HttpResponse("Referer URL not provided.", status_code=400)
