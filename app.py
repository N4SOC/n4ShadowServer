import config
import requests
import json
import hmac
import hashlib

import azloganalytics

la = azloganalytics.LogAnalytics(config.azID, config.azSecret, "shadowserver") # Create log analytics object with creds & table


def genHMAC(secret, request): # Generate SHA256 HMAC from request & secret
    request_string = json.dumps(request)
    secret_bytes = bytes(str(secret), 'utf-8')
    request_bytes = bytes(request_string, 'utf-8')
    hmac_generator = hmac.new(secret_bytes, request_bytes, hashlib.sha256)
    hmac2 = hmac_generator.hexdigest()
    return hmac2


def listReports(): #Get list of available reports
    req = {"id": "", "limit": 100, "apikey": f"{config.key}"}
    url = 'https://transform.shadowserver.org/api2/reports/list'
    resp = requests.post(url, json=req, headers={"HMAC2": genHMAC(secret=config.secret, request=req)})
    return resp.json()


def downloadReport(reportID): # Retreive data from specified report
    req = {"id": reportID, "limit": 5000, "apikey": f"{config.key}"}
    url = 'https://transform.shadowserver.org/api2/reports/download'
    resp = requests.post(url, json=req, headers={"HMAC2": genHMAC(secret=config.secret, request=req)})
    return resp.json()


for report in listReports():
    if report['type']!="device_id":
        reportContent = downloadReport(report['id'])
        print(f"Report: {report['type']} - Records: {len(reportContent)}")
        if len(reportContent)==5000:
            print("** LIMIT REACHED - Results Truncated")
        for device in reportContent:
            if "ip" in device:
                device['scan'] = report['type']
                deviceJSON = []
                deviceJSON.append(device)
                la.sendtoAzure(deviceJSON) # Not working?
                # print(deviceJSON) # Remove for prod
