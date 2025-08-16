from flask import Flask, request, jsonify
import requests
import os
import base64
import joblib
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# VirusTotal API key
VT_API_KEY = os.getenv("VT_API_KEY")
if not VT_API_KEY:
    raise ValueError("❌ VirusTotal API key not found. Please set VT_API_KEY in .env")

VT_HEADERS = {"x-apikey": VT_API_KEY}

# Load trained ML model
model = joblib.load("random_forest_model.joblib")

# -------------------------
# Feature extraction (must match training)
# -------------------------
def extract_features(url: str):
    return [
        len(url),
        url.count('.'),
        url.count('-'),
        url.count('@'),
        url.startswith("https"),
        sum(c.isdigit() for c in url)
    ]

def check_with_model(url: str) -> str:
    try:
        features = [extract_features(url)]
        prediction = model.predict(features)[0]
        return "phishing" if prediction == 1 else "safe"
    except Exception as e:
        return f"error: {str(e)}"

def check_with_virustotal(url: str):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(report_url, headers=VT_HEADERS)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            if stats["malicious"] > 0 or stats["suspicious"] > 0:
                return {"status": "phishing", "details": stats}
            else:
                return {"status": "safe", "details": stats}
        else:
            return {"status": "error", "message": f"VT error {response.status_code}"}

    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    url = data.get("url")

    model_result = check_with_model(url)
    vt_result = check_with_virustotal(url)

    return jsonify({
        "url": url,
        "model_result": model_result,
        "virustotal_result": vt_result["status"],
        "virustotal_details": vt_result.get("details", {}),
        "message": vt_result.get("message", "")
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)
