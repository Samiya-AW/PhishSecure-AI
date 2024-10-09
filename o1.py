import os
import re
import sys
import json
from openai import OpenAI
from dotenv import load_dotenv
from test import scan_urls

load_dotenv()

def extract_urls(email_content):
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, email_content)

def analyze_email(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            email_content = file.read()

        urls = extract_urls(email_content)
        scan_results = scan_urls(urls)

        messages = [
            {"role": "assistant", "content": "You are an advanced AI assistant specialized in cybersecurity and email threat analysis. Your primary task is to examine email content and URL scan results to identify potential phishing attempts."},
            {"role": "assistant", "content": f"Please analyze the following email content for any signs of phishing:\n\n{email_content}"},
            {"role": "assistant", "content": f"Here are the URL scan results associated with the email:\n\n{json.dumps(scan_results, indent=2)}"},
            {"role": "assistant", "content": "Based on the provided email content and URL scan results, please perform the following tasks:"
             "1. Identify any suspicious elements in the email content (e.g., urgent language, requests for sensitive information, unexpected attachments)."
             "2. Analyze the URL scan results for any red flags (e.g., mismatched domains, recently registered websites, low reputation scores)."
             "3. Correlate findings from the email content and URL scan to form a comprehensive assessment."
             "4. Conclude whether the email is a phishing attempt or not."
             "5. If it is a phishing attempt, provide detailed reasons based on your analysis of both the email content and scan results."
             "6. If it is not a phishing attempt, explain why you've reached this conclusion, citing specific elements that indicate legitimacy."
             "7. Offer any additional security recommendations or best practices relevant to this specific case."}
        ]

        client = OpenAI(
            api_key=os.getenv('OPENAI_API_KEY'),
            base_url="https://api.aimlapi.com/",
        )

        chat_completion = client.chat.completions.create(
            model="o1-preview",
            messages=messages,
            max_tokens=6500,
        )

        response = chat_completion.choices[0].message.content
        return json.dumps({"result": response})
    except Exception as e:
        return json.dumps({"error": str(e)})

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No file path provided"}))
    else:
        file_path = sys.argv[1]
        result = analyze_email(file_path)
        print("DEBUG_OUTPUT_START")
        print(scan_urls(extract_urls(open(file_path, 'r', encoding='utf-8').read())))
        print("DEBUG_OUTPUT_END")
        print(result)