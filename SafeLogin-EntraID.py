import azure.functions as func
import logging
import requests
from urllib.parse import urlparse

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="safelogin_trigger")
def safelogin_trigger(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processing a request.')

    # Get the Referer header to verify the URL
    referer_url = req.headers.get('Referer')

    # Legitimate base URLs for validation
    valid_urls = [
        f"https://login.microsoftonline.com/"
    ]

    if referer_url:
        # Extract the base URL (path without parameters) for validation
        parsed_url = urlparse(referer_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

        logging.info(f"Referer URL: {referer_url}")
        logging.info(f"Base URL: {base_url}")

        # Check if the referer's base URL is one of the legitimate URLs
        if base_url in valid_urls:
            # If the URL is legitimate, return a 204 No Content status
            return func.HttpResponse(status_code=204)
        else:
            # If the URL is not legitimate, try returning the phishing image directly from Blob Storage
            image_url = "Your-ImageAlert-URL-Here"
            image_response = requests.get(image_url)

            if image_response.status_code == 200:
                return func.HttpResponse(image_response.content, mimetype="image/png", status_code=200)
            else:
                logging.error(f"Error loading phishing alert image. URL Referer: {referer_url}")
                return func.HttpResponse("Error loading alert image", status_code=500)
    else:
        logging.error("Referer URL is not provided or is empty.")
        return func.HttpResponse("Referer URL was not provided", status_code=400)
