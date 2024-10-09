import requests
import base64
import os
import time
from dotenv import load_dotenv

load_dotenv()

def scan_urls(urls):
    # API key and URL to scan
    api_key = os.getenv('VT_API_KEY')
    
    for url_to_scan in urls:
        # Encode the URL in base64 (without padding '=')
        url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().rstrip("=")

        # Endpoint to submit URL
        submit_url = "https://www.virustotal.com/api/v3/urls"

        # Submit the URL for scanning
        payload = {"url": url_to_scan}
        headers = {
            "accept": "application/json",
            "x-apikey": api_key,
            "content-type": "application/x-www-form-urlencoded"
        }

        response = requests.post(submit_url, data=payload, headers=headers)
        result = response.json()

        # Check for 'data' key in the result
        if 'data' in result:
            analysis_id = result['data']['id']
            print("Analysis ID for URL:", url_to_scan, "is", analysis_id)

            # Endpoint to retrieve the analysis results
            retrieve_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

            # Wait a few seconds before retrieving to ensure analysis is complete
            time.sleep(10)

            # Get the analysis results
            headers = {
                "accept": "application/json",
                "x-apikey": api_key
            }

            response = requests.get(retrieve_url, headers=headers)
            analysis_result = response.json()

            # Print the analysis result
            print("Analysis result for URL:", url_to_scan, "is", analysis_result)
        else:
            print("Key 'data' not found in result for URL:", url_to_scan, "Result:", result)

# Example usage
urls_to_scan = [
    "https://ssl-lqhcxkr4ta.artbyhanna.de/simply/cart/web/pay.php",
    # Add more URLs as needed
]
scan_urls(urls_to_scan)
