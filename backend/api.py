from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
from scanner.websitestresser import SocketStress
from scanner.sql_injection import sqlscanner
from scanner.xss import xssVulnurable
from scanner.weak_passwords import weakpasswords
from scanner.deface import defacesite
from scanner.dnsrecords import find_dns_records
from scanner.fullscan import full_attack
from scanner.generalinfo import gather_website_info

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ["http://localhost:3000"]}})

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Health check endpoint
@app.route('/health', methods=["GET"])
def health_check():
    try:
        return jsonify({"status": "healthy", "message": "Backend server is running"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# Scan endpoints
@app.route('/sqlscan', methods=["POST"])
def sqlscan():
    try:
        data = request.get_json()
        url = data.get("website")
        if not url:
            return jsonify({"error": "No website URL provided"}), 400
        status_code, message = sqlscanner(url)
        return jsonify(message), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/password', methods=["POST"])
def passwords():
    try:
        data = request.get_json()
        url = data.get("website")
        if not url:
            return jsonify({"error": "No website URL provided"}), 400
        status_code, message = weakpasswords(url)
        return jsonify(message), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/webstresser', methods=["POST"])
def webstresser():
    try:
        data = request.get_json()
        url = data.get("website")
        if not url:
            return jsonify({"error": "No website URL provided"}), 400
        status_code, message = SocketStress(url)
        return jsonify(message), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/xss', methods=["POST"])
def xss():
    try:
        data = request.get_json()
        url = data.get("website")
        if not url:
            return jsonify({"error": "No website URL provided"}), 400
        status_code, message = xssVulnurable(url)
        return jsonify(message), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/deface', methods=['POST'])
def deface():
    try:
        data = request.get_json()
        url = data.get("website")
        if not url:
            return jsonify({"error": "No website URL provided"}), 400
        status_code, message = defacesite(url)
        return jsonify(message), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/basicscan', methods=['POST'])
def basicscan():
    try:
        data = request.get_json()
        url = data.get("website")
        if not url:
            return jsonify({"error": "No website URL provided"}), 400
        status_code, message = gather_website_info(url)
        return jsonify(message), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/dnsrecord', methods=['POST'])
def dnsrecords():    
    try:
        data = request.get_json()
        url = data.get("website")
        if not url:
            return jsonify({"error": "No website URL provided"}), 400
        status_code, message = find_dns_records(url)
        return jsonify(message), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/scanner/fullscan', methods=['POST'])
def fullscan():
    try:
        data = request.get_json()
        url = data.get("website")
        if not url:
            return jsonify({"error": "No website URL provided"}), 400
        status_code, message = full_attack(url)
        return jsonify(message), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10037, debug=True)