import time
from zapv2 import ZAPv2
import pandas as pd
from flask import Flask, jsonify, request

app = Flask(__name__)
# Enable CORS for frontend testing
from flask_cors import CORS
CORS(app)



apiKey = 'bk25pnr21gmnpbfqkk8sjedci9'
target = 'https://public-firing-range.appspot.com'
zap = ZAPv2(apikey=apiKey, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})



#for doing a SPIDER
def init_spider(target, zap = zap):
    scanID = zap.spider.scan(target)
    while int(zap.spider.status(scanID)) < 100:
        print('Spider progress %: {}'.format(zap.spider.status(scanID)))
        time.sleep(1)

    print('Spider has completed!')



#for doing a passive scan
def passive_scan(zap = zap):
    
    #check if spider exists
    if zap.spider.status("0") == "does_not_exist":
        print('initializing spider')
        init_spider(target=target)
    else:
        print("spider exists")

    #passive scan code
    while int(zap.pscan.records_to_scan) > 0:
        # Loop until the passive scan has finished
        print('Records to passive scan : ' + zap.pscan.records_to_scan)
        time.sleep(2)

    print('Passive Scan completed')

    # Print Passive scan results/alerts
    # print('Hosts: {}'.format(', '.join(zap.core.hosts)))
    # print('Alerts: ')
    # pprint(zap.core.alerts())

    #storing the data in a dataframe
    alerts = zap.core.alerts()
    df = pd.json_normalize(alerts, sep='_')
    #some basic data cleaning
    df = df.drop(['sourceid', 'sourceMessageId', 'messageId', 'pluginId', 'alertRef','method', 'param', 'inputVector', 'attack', 'evidence','name', 'id', 'wascid', 'cweid', 'other' ],
                axis=1)

    #storing the dataframe in a json file
    df.to_json('table.json')
    return df.to_dict(orient="records")


# API to Start Scan
@app.route('/scan', methods=['GET'])
def scan():
    passive_scan()
    return jsonify({"message": "Scan completed! Use /results to see findings."})

# API to Fetch Results
@app.route('/results', methods=['GET'])
def get_results():
    try:
        df = pd.read_json('table.json')
        return jsonify(df.to_dict(orient="records"))
    except Exception as e:
        return jsonify({"error": str(e)})

# Run Flask App
if __name__ == '__main__':
    app.run(debug=True)

