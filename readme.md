# OWASP ZAP Security Dashboard

A Python Flask web application that integrates
with OWASP ZAP to perform automated security
testing on web applications.

## Features
- Spider Scan — discovers all URLs on target
- Passive Scan — detects security misconfigurations
- Active Scan — simulates real attacks on target
- Report Generation — downloads HTML security report
- Color coded results — High/Medium/Low/Info

## Tech Stack
- Python 3.13
- Flask
- OWASP ZAP 2.17.0
- python-owasp-zap-v2.4
- HTML/CSS

## Project Structure
OWASP-ZAP-PROJECT/
├── app.py              # Main Flask application
├── zap_helper.py       # ZAP API helper functions
├── target_app.py       # Vulnerable test application
├── requirements.txt    # Python dependencies
├── templates/
│   └── index.html      # Dashboard HTML
├── static/
│   └── style.css       # Dashboard CSS
└── reports/            # Generated scan reports

## Setup Instructions

1. Clone the repository
git clone https://github.com/yourusername/OWASP-ZAP-PROJECT.git
cd OWASP-ZAP-PROJECT

2. Create virtual environment
python -m venv .venv
.venv\Scripts\activate

3. Install dependencies
pip install -r requirements.txt

4. Start OWASP ZAP
- Open OWASP ZAP application
- Go to Tools → Options → API
- Copy your API key
- Paste in zap_helper.py

5. Run target app
python target_app.py

6. Run dashboard
python app.py

7. Open browser
http://127.0.0.1:5000

## Usage
1. Open dashboard at 127.0.0.1:5000
2. Click Run Spider — discovers URLs
3. Click Run Passive Scan — finds misconfigurations
4. Click Run Active Scan — simulates attacks
5. Click Download Report — saves HTML report

## Warning
target_app.py is intentionally vulnerable.
Run locally only — never deploy publicly.