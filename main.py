from flask import Flask, jsonify, request
import time
from zapv2 import ZAPv2
import pandas as pd
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

from flask_cors import CORS
CORS(app)

apiKey = 'bk25pnr21gmnpbfqkk8sjedci9'
zap = ZAPv2(apikey=apiKey, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})

# Spider Function
def init_spider(target):
    scanID = zap.spider.scan(target)
    while int(zap.spider.status(scanID)) < 100:
        time.sleep(1)
    print('Spider has completed!')

# GDPR/CCPA Compliance Scanner
def passive_scan(target):
    init_spider(target)

    while int(zap.pscan.records_to_scan) > 0:
        time.sleep(2)

    alerts = zap.core.alerts()
    df = pd.json_normalize(alerts, sep='_')

    # Keep relevant security alerts
    df = df[['alert', 'risk', 'confidence', 'description', 'solution', 'reference']]

    # Additional Compliance Checks
    compliance_issues = []
    
    # Fetch page HTML
    try:
        response = requests.get(target, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
    
        # Check for Cookie Consent Banner
        cookie_keywords = ['cookie', 'consent', 'gdpr']
        if not any(keyword in response.text.lower() for keyword in cookie_keywords):
            compliance_issues.append({
                "alert": "Missing Cookie Consent Banner",
                "risk": "High",
                "confidence": "High",
                "description": "No cookie consent banner detected. This may violate GDPR requirements.",
                "solution": "Ensure a consent banner is present and allows users to opt in/out of tracking.",
                "reference": "https://gdpr.eu/cookies/"
            })
    
        # Check for Privacy Policy Link
        privacy_keywords = ['privacy policy', 'terms of service', 'terms & conditions']
        if not any(link.text.lower() in privacy_keywords for link in soup.find_all('a')):
            compliance_issues.append({
                "alert": "Missing Privacy Policy",
                "risk": "High",
                "confidence": "High",
                "description": "Privacy policy not found on the website. This may violate GDPR/CCPA regulations.",
                "solution": "Ensure a clear and accessible Privacy Policy link is present on the homepage.",
                "reference": "https://gdpr.eu/privacy-notice/"
            })
    
        # Check for Data Collection Without Disclosure
        sensitive_inputs = ['email', 'phone', 'address', 'name']
        for input_tag in soup.find_all('input'):
            if any(field in str(input_tag).lower() for field in sensitive_inputs):
                compliance_issues.append({
                    "alert": "Potential Data Collection Without Disclosure",
                    "risk": "Medium",
                    "confidence": "Medium",
                    "description": "Detected input fields that collect user data but no visible disclosure statement.",
                    "solution": "Ensure users are informed about data collection and consent is obtained.",
                    "reference": "https://gdpr.eu/consent/"
                })
    
        # Check for Third-Party Trackers
        trackers = {
            'Google Analytics': 'www.google-analytics.com',
            'Facebook Pixel': 'connect.facebook.net'
        }
        for tracker, domain in trackers.items():
            if domain in response.text:
                compliance_issues.append({
                    "alert": f"{tracker} Tracker Detected",
                    "risk": "Medium",
                    "confidence": "High",
                    "description": f"Detected {tracker} tracking scripts. Ensure users are informed and provide consent.",
                    "solution": "Inform users about third-party tracking in the privacy policy and allow opt-out.",
                    "reference": "https://gdpr.eu/cookies/"
                })
    except Exception as e:
        print(f"Error fetching website: {e}")

    # Append Compliance Issues
    df = pd.concat([df, pd.DataFrame(compliance_issues)], ignore_index=True)
    df.to_json('table.json')
    return df.to_dict(orient="records")

# API to Start Scan
@app.route('/scan', methods=['GET'])
def scan():
    target_url = request.args.get('url')
    if not target_url:
        return jsonify({"error": "Missing target URL"}), 400

    scan_results = passive_scan(target_url)
    return jsonify({"message": f"Scan completed for {target_url}", "results": scan_results})

# API to Fetch Results
@app.route('/results', methods=['GET'])
def get_results():
    try:
        df = pd.read_json('table.json')
        return jsonify(df.to_dict(orient="records"))
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    app.run(debug=True)
