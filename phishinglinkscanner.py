from flask import Flask, render_template, request
import re
import validators
import requests
import base64

app = Flask(__name__)

# Function to check for phishing patterns in URLs
def is_phishing_url(url):
    if not validators.url(url):
        return False

    phishing_keywords = ['login', 'secure', 'account', 'verify', 'password', 'update']
    if any(keyword in url.lower() for keyword in phishing_keywords):
        return True

    if re.search(r'[a-zA-Z0-9]+\.[a-zA-Z]{2,3}\.[a-zA-Z]{2,3}', url):
        return True

    return False

# Function to check the reputation of a URL using VirusTotal
def check_url_reputation(url):
    api_key = '3143d82ef519bed1c2385770bdf702edd8417833676f8e8ae6e5514459b452e8'  # Replace with your VirusTotal API key
    headers = {"x-apikey": api_key}
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{encoded_url}", headers=headers)

    if response.status_code == 200:
        json_response = response.json()
        if json_response['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            return True
    return False

@app.route('/', methods=['GET', 'POST'])
def index():
    result = ""
    if request.method == 'POST':
        url = request.form['url']
        if not url:
            result = "Please enter a URL."
        else: 
            phishing_flag = False
            if is_phishing_url(url):
                result = "Warning: This URL has phishing characteristics."
                phishing_flag = True
            elif check_url_reputation(url):
                result = "Warning: This URL has been marked as malicious by VirusTotal."
                phishing_flag = True
            else:
                result = "The URL seems safe based on current checks."

    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
