from flask import Flask, jsonify, request
import time
from zapv2 import ZAPv2
import pandas as pd

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

# Passive Scan Function
def passive_scan(target):
    init_spider(target)

    while int(zap.pscan.records_to_scan) > 0:
        time.sleep(2)

    alerts = zap.core.alerts()
    df = pd.json_normalize(alerts, sep='_')

    df = df.drop(
        ['sourceid', 'sourceMessageId', 'messageId', 'pluginId', 'alertRef',
         'method', 'param', 'inputVector', 'attack', 'evidence', 'name',
         'id', 'wascid', 'cweid', 'other'], axis=1)

    df.to_json('data/table.json')
    return df.to_dict(orient="records")

# API to Start Scan (with User Input)
@app.route('/scan', methods=['GET'])
def scan():
    target_url = request.args.get('url')
    if not target_url:
        return jsonify({"error": "Missing target URL"}), 400

    passive_scan(target_url)
    return jsonify({"message": f"Scan completed for {target_url}. Use /results to see findings."})

# API to Fetch Results
@app.route('/results', methods=['GET'])
def get_results():
    try:
        df = pd.read_json('data/table.json')

        # Keep only the necessary columns
        df = df[['alert', 'risk', 'confidence', 'description', 'solution', 'reference']]

        return jsonify(df.to_dict(orient="records"))
    except Exception as e:
        return jsonify({"error": str(e)})


if __name__ == '__main__':
    app.run(debug=True)
