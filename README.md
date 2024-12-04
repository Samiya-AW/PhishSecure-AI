# PhishSecure AI

PhishSecure AI is an AI-powered web application that detects phishing emails by analyzing email content and URLs, providing users with detailed analysis and recommended actions to enhance their email security.

## Features

* Phishing detection through AI content analysis.
* URL checking against known malicious databases.
* User-friendly interface for email analysis.

## Technology Used

* OpenAI o1 Model
* Python (Flask)
* Gmail API
* PhishTank API
* Google Safe Browsing API
* Frontend: HTML, CSS, JavaScript

## Getting Started

### Prerequisites

* Python 3.11
* Node.js
* npm (Node Package Manager)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Samiya-AW/PhishSecure-AI.git
   cd PhishSecure-AI
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install Node.js dependencies:
   ```bash
   npm install
   ```

4. Set up environment variables:
   Create a `.env` file in the root directory and add the following variables:
   ```env
   VT_API_KEY=your_virustotal_api_key
   GMAIL_USER=your_gmail_user
   GMAIL_APP_PASSWORD=your_gmail_app_password
   SECRET_KEY=your_flask_secret_key
   OPENAI_API_KEY=your_openai_api_key
   ```

## Running the Application

1. Start the Flask server:
   ```bash
   python app.py
   ```

2. Start the Next.js development server:
   ```bash
   npm run dev
   ```

3. Open http://localhost:3000 in your browser to see the application.

## Usage

1. Upload the email (.eml) file you suspect might be a phishing attempt.
2. Click "Analyze Email" to check its safety.
3. View the analysis result and follow the recommended actions.

## Contributing

Contributions are welcome! Please fork the repository and create a pull request with your changes.

## License

This project is licensed under the MIT License.
