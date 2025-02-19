import lightgbm as lgb
import psutil
import socket
import scapy.all as scapy
import threading
import time
import json
import os
import numpy as np
from flask import Flask, render_template, jsonify, request
from google.colab import drive
from keras.models import Model
from keras.layers import Input, Dense
from keras.optimizers import Adam
import subprocess

# ---------------------- Google Drive Setup ----------------------
drive.mount('/content/drive')
STORAGE_PATH = '/content/drive/MyDrive/cybersecurity_ai/'
os.makedirs(STORAGE_PATH, exist_ok=True)
MODEL_FILE = os.path.join(STORAGE_PATH, 'model.txt')
THREAT_LOG_FILE = os.path.join(STORAGE_PATH, 'threats_log.json')

# ---------------------- Ngrok Setup ----------------------
!pip install pyngrok --quiet
from pyngrok import ngrok

ngrok.set_auth_token("2slGI9SSO1EQPEtskTfwugSNqEq_KFE4Esc9A7VMC1mJYBnr")  # Replace with your actual token
public_url = ngrok.connect(5000)
print(f"🚀 Public URL: {public_url}")

# ---------------------- Global Variables ----------------------
THREATS_LOG = []
WHITELIST = set()
BLACKLIST = set()

if os.path.exists(THREAT_LOG_FILE):
    with open(THREAT_LOG_FILE, 'r') as f:
        THREATS_LOG = json.load(f)

# ---------------------- System Resource Monitoring ----------------------
def check_system_resources():
    cpu = psutil.cpu_percent()
    memory = psutil.virtual_memory().percent
    return {'cpu': cpu, 'memory': memory, 'alert': cpu > 85 or memory > 85}

# ---------------------- Data Collection ----------------------
def get_network_activity():
    packets = scapy.sniff(count=50, timeout=5)
    features, connections = [], []
    for packet in packets:
        if packet.haslayer(scapy.IP):
            features.append([
                len(packet),
                packet[scapy.IP].ttl,
                packet[scapy.IP].id,
                int(packet.haslayer(scapy.TCP)),
                int(packet.haslayer(scapy.UDP))
            ])
            connections.append(packet[scapy.IP].src)
    return np.array(features), connections

# ---------------------- Model Handling ----------------------
def load_or_train_model():
    if os.path.exists(MODEL_FILE):
        model = lgb.Booster(model_file=MODEL_FILE)
    else:
        train_data = lgb.Dataset(np.array([[0, 0, 0, 0, 0]]), label=np.array([0]))
        model = lgb.train({'objective': 'binary', 'verbosity': -1}, train_data, num_boost_round=10)
        model.save_model(MODEL_FILE)
    return model

# ---------------------- Detection & Defense ----------------------
def detect_threat(model, features, ips):
    predictions = model.predict(features)
    threats = []
    for ip, pred in zip(ips, predictions):
        if pred > 0.7 and ip not in WHITELIST:
            threat = {'ip': ip, 'threat_level': round(float(pred), 2), 'time': time.strftime('%Y-%m-%d %H:%M:%S')}
            THREATS_LOG.append(threat)
            threats.append(ip)
    with open(THREAT_LOG_FILE, 'w') as f:
        json.dump(THREATS_LOG, f, indent=4)
    return threats

# ---------------------- Flask App ----------------------
app = Flask(__name__, template_folder='templates')

@app.route('/')
def dashboard():
    return render_template('dashboard.html', threats=THREATS_LOG, system=check_system_resources())

@app.route('/threats')
def get_threats():
    return jsonify(THREATS_LOG)

@app.route('/resource-status')
def resource_status():
    return jsonify(check_system_resources())

@app.route('/whitelist', methods=['POST'])
def add_to_whitelist():
    ip = request.json.get('ip')
    WHITELIST.add(ip)
    return jsonify({'status': 'success', 'whitelisted_ip': ip})

@app.route('/blacklist', methods=['POST'])
def add_to_blacklist():
    ip = request.json.get('ip')
    BLACKLIST.add(ip)
    return jsonify({'status': 'success', 'blacklisted_ip': ip})

# ---------------------- HTML Template ----------------------
os.makedirs('templates', exist_ok=True)
with open('templates/dashboard.html', 'w') as f:
    f.write('''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cybersecurity AI Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f2f5; color: #333; padding: 20px; }
        .card { background: white; border-radius: 15px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); padding: 20px; margin: 20px 0; }
        h1 { font-size: 28px; color: #2c3e50; }
        button { padding: 10px 20px; border: none; border-radius: 10px; background: #3498db; color: white; cursor: pointer; margin: 5px; }
        button:hover { background: #2980b9; }
        ul { list-style-type: none; padding: 0; }
        li { background: #ecf0f1; margin: 5px 0; padding: 10px; border-radius: 8px; }
    </style>
</head>
<body>
    <h1>🚀 Cybersecurity AI Dashboard</h1>
    <div class="card">
        <h3>🔎 System Resource Status</h3>
        <p>CPU Usage: {{ system['cpu'] }}%</p>
        <p>Memory Usage: {{ system['memory'] }}%</p>
        {% if system['alert'] %}<p style="color:red;">⚠️ High resource usage!</p>{% endif %}
        <button onclick="fetch('/resource-status').then(r=>r.json()).then(d=>alert(`CPU: ${d.cpu}% | Memory: ${d.memory}%`))">Check Resources</button>
    </div>
    <div class="card">
        <h3>📄 Threat Logs</h3>
        <ul>
            {% for threat in threats %}
                <li>🛑 IP: {{ threat.ip }} | Threat Level: {{ threat.threat_level }} | Time: {{ threat.time }}</li>
            {% endfor %}
        </ul>
        <button onclick="fetch('/threats').then(r=>r.json()).then(d=>alert(JSON.stringify(d, null, 2)))">View All Threats</button>
    </div>
</body>
</html>''')

# ---------------------- Run Server ----------------------
if __name__ == "__main__":
    app.run(port=5000)
