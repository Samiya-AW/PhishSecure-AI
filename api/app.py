# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import os
import imaplib
import email
from email import policy
from email.parser import BytesParser
import requests
from werkzeug.utils import secure_filename
from dotenv import load_dotenv


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# @app.route('/')
# def home():
#     return jsonify(message="Hello, PhishSecure AI!")

# Expose the WSGI application for Vercel
def handler(request, context):
    return app.full_dispatch_request()

load_dotenv()
vt_api_key = os.getenv('VT_API_KEY')
gmail_user = os.getenv('GMAIL_USER')
gmail_app_password = os.getenv('GMAIL_APP_PASSWORD')
secret_key = os.getenv('SECRET_KEY')


app.secret_key = secret_key  # Replace with a secure key
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max upload size: 16MB

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'eml'}


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/', methods=['GET', 'POST'])
def index():
    analysis_result = None
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'email_file' not in request.files:
            flash('No file part in the form.')
            return redirect(request.url)

        file = request.files['email_file']

        # If user does not select file, browser may submit an empty part
        if file.filename == '':
            flash('No file selected.')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Extract email content
            email_content = extract_email_content(filepath)

            # Analyze email content using VirusTotal API and Gmail IMAP
            analysis_result = analyze_email(email_content)

            return render_template('index.html', analysis_result=analysis_result)
        else:
            flash('Invalid file type. Please upload a .eml file.')
            return redirect(request.url)

    return render_template('index.html', analysis_result=analysis_result)


def extract_email_content(filepath):
    with open(filepath, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
        # Extract plain text content; adjust if needed
        body = msg.get_body(preferencelist=('plain'))
        if body:
            return body.get_content()
        else:
            return ''


def analyze_email(email_content):
    # Step 1: Extract URLs from the email content
    urls = extract_urls(email_content)

    # Step 2: Scan URLs using VirusTotal API
    vt_results = scan_urls_virustotal(urls)

    # Step 3: Analyze email content using O1-Preview Model (Placeholder)
    # Replace this with actual model integration
    email_analysis = analyze_with_model(email_content)

    # Step 4: Compile the results
    if vt_results['is_phishing'] or email_analysis['is_phishing']:
        verdict = 'This email appears to be a phishing attempt!'
        reasons = []
        if vt_results['is_phishing']:
            reasons.append('Contains suspicious links.')
        if email_analysis['is_phishing']:
            reasons.append('Detected patterns commonly found in phishing emails.')
        recommendations = 'Do not click any links and delete the email.'
        is_phishing = True
    else:
        verdict = 'This email appears to be safe.'
        reasons = ['No suspicious content detected.']
        recommendations = 'No action needed.'
        is_phishing = False

    return {
        'is_phishing': is_phishing,
        'verdict': verdict,
        'reasons': reasons,
        'recommendations': recommendations
    }


def extract_urls(text):
    import re
    # Simple regex to extract URLs; consider using more robust methods if needed
    url_pattern = re.compile(r'https?://\S+')
    urls = re.findall(url_pattern, text)
    return urls


def scan_urls_virustotal(urls):
    api_key = '576d865895f3baf1e3f852fbc8e8348ca9b8a8425d78d1b23c413bb5eb818001'  # Replace with your VirusTotal API key
    headers = {
        'x-apikey': api_key
    }
    is_phishing = False
    scan_results = []

    for url in urls:
        response = requests.get(f'https://www.virustotal.com/api/v3/urls/{encode_url(url)}', headers=headers)
        if response.status_code == 404:
            # URL not found in VirusTotal, submit it for analysis
            response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data={'url': url})
            if response.status_code == 200:
                analysis_url = response.json()['data']['id']
                scan_results.append({'url': url, 'status': 'submitted'})
            else:
                scan_results.append({'url': url, 'status': 'error submitting'})
        elif response.status_code == 200:
            # Retrieve analysis
            analysis = response.json()
            malicious = analysis['data']['attributes']['last_analysis_stats']['malicious']
            if malicious > 0:
                is_phishing = True
                scan_results.append({'url': url, 'status': 'malicious'})
            else:
                scan_results.append({'url': url, 'status': 'safe'})
        else:
            scan_results.append({'url': url, 'status': 'error retrieving'})

    return {'is_phishing': is_phishing, 'scan_results': scan_results}


def encode_url(url):
    import base64
    # URL must be base64url encoded without padding
    url_bytes = url.encode('utf-8')
    encoded = base64.urlsafe_b64encode(url_bytes).decode('utf-8').rstrip('=')
    return encoded


def analyze_with_model(email_content):
    # Placeholder for integrating the O1-Preview Model
    # Replace with actual model inference
    # For demonstration, we'll assume any email containing "urgent" is phishing
    if "urgent" in email_content.lower():
        return {'is_phishing': True}
    else:
        return {'is_phishing': False}


if __name__ == '__main__':
    app.run(debug=True)


def fetch_unread_emails():
    imap_host = 'imap.gmail.com'
    imap_user = 'your_email@gmail.com'      # Replace with your email
    imap_pass = 'your_app_password'         # Replace with your App Password

    try:
        mail = imaplib.IMAP4_SSL(imap_host)
        mail.login(imap_user, imap_pass)
        mail.select('inbox')  # Select the mailbox you want to use

        # Search for all unread emails
        result, data = mail.search(None, '(UNSEEN)')
        if result != 'OK':
            print('No unread emails found!')
            return []

        email_ids = data[0].split()
        emails = []

        for eid in email_ids:
            result, msg_data = mail.fetch(eid, '(RFC822)')
            if result != 'OK':
                print(f'ERROR getting message {eid}')
                continue

            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email, policy=policy.default)
            emails.append(msg)

            # Optionally mark the email as seen
            mail.store(eid, '+FLAGS', '\\Seen')

        mail.logout()
        return emails

    except imaplib.IMAP4.error as e:
        print(f'IMAP error: {e}')
        return []


@app.route('/fetch-emails', methods=['GET'])
def fetch_emails():
    try:
        # Connect to Gmail via IMAP
        mail = imaplib.IMAP4_SSL('imap.gmail.com')
        mail.login(gmail_user, gmail_app_password)
        mail.select('inbox')  # Connect to inbox.

        # Search for all emails
        result, data = mail.search(None, 'ALL')
        email_ids = data[0].split()

        emails = []
        for eid in email_ids:
            result, msg_data = mail.fetch(eid, '(RFC822)')
            if result == 'OK':
                msg = email.message_from_bytes(msg_data[0][1], policy=policy.default)
                subject = msg['subject']
                from_ = msg['from']
                body = ''
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == 'text/plain':
                            body += part.get_content()
                else:
                    body = msg.get_content()

                # Analyze email
                analysis = analyze_email(body)

                emails.append({
                    'subject': subject,
                    'from': from_,
                    'body': body,
                    'analysis': analysis
                })

        mail.logout()

        return render_template('fetch_emails.html', emails=emails)
    except Exception as e:
        print(f"Error fetching emails: {e}")
        flash('An error occurred while fetching emails. Please try again later.')
        return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)