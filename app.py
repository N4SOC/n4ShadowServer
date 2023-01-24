import config
import requests
import json
import hmac
import hashlib

import azloganalytics

la = azloganalytics.LogAnalytics(config.azID, config.azSecret, "shadowserver")


def listReports():
    req = {"id": "", "limit": 5, "apikey": f"{config.key}"}
    url = 'https://transform.shadowserver.org/api2/reports/list'
    request_string = json.dumps(req)

    secret_bytes = bytes(str(config.secret), 'utf-8')
    request_bytes = bytes(request_string, 'utf-8')

    hmac_generator = hmac.new(secret_bytes, request_bytes, hashlib.sha256)
    hmac2 = hmac_generator.hexdigest()

    resp = requests.post(url, json=req, headers={"HMAC2": hmac2})

    return resp.json()


def downloadReport(reportID):
    req = {"id": reportID, "limit": 5, "apikey": f"{config.key}"}
    url = 'https://transform.shadowserver.org/api2/reports/download'
    request_string = json.dumps(req)

    secret_bytes = bytes(str(config.secret), 'utf-8')
    request_bytes = bytes(request_string, 'utf-8')

    hmac_generator = hmac.new(secret_bytes, request_bytes, hashlib.sha256)
    hmac2 = hmac_generator.hexdigest()

    resp = requests.post(url, json=req, headers={"HMAC2": hmac2})

    return resp.json()


for report in listReports():
    print(report['type'])
    reportContent = downloadReport(report['id'])
    for device in reportContent:
        if "ip" in device:
            deviceJSON = {}
            la.sendtoAzure(deviceJSON)
