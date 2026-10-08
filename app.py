from flask import Flask, render_template, request, redirect, url_for
import pandas as pd
import os
import subprocess

app = Flask(__name__)

LOG_FILE = "logs/security_log.csv"

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/activate', methods=['POST'])
def activate():
    ip = request.form['ip']
    return redirect(url_for('dashboard', ip=ip))

@app.route('/dashboard')
def dashboard():
    ip = request.args.get('ip')

    logs = []
    threat_count = 0

    if os.path.exists(LOG_FILE):
        df = pd.read_csv(LOG_FILE)
        logs = df.tail(10).to_dict(orient='records')
        threat_count = len(df)

    metrics = {
        "accuracy": "96%",
        "precision": "84%",
        "recall": "100%",
        "f1": "92%"
    }

    return render_template(
        "dashboard.html",
        ip=ip,
        logs=logs,
        threat_count=threat_count,
        metrics=metrics
    )
@app.route('/run_nmap')
def run_nmap():
    import os
    os.system("start cmd /k nmap -Pn -sS -T4 -p 1-1000 10.1.28.33")
    return redirect(request.referrer)
if __name__ == '__main__':
    app.run(debug=True)