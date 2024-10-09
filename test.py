import requests
import base64
import os

from dotenv import load_dotenv



load_dotenv()

def scan_urls(urls):
    # API key and URL to scan
    api_key = os.getenv('VT_API_KEY')
    scan_results = {}  # Dictionary to store results for each URL

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

            

            # Get the analysis results
            headers = {
                "accept": "application/json",
                "x-apikey": api_key
            }

            response = requests.get(retrieve_url, headers=headers)
            analysis_result = response.json()

            #result = DDGS().chat(f"summarize the result : {analysis_result}", model='claude-3-haiku')


            # Store the analysis result
            scan_results[url_to_scan] = analysis_result
        else:
            print("Key 'data' not found in result for URL:", url_to_scan, "Result:", result)
            scan_results[url_to_scan] = "Error: No data found"

    return scan_results  # Return the collected results

# Example usage
