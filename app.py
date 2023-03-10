import config
import requests
import json
import hmac
import hashlib
import ipaddress

import azloganalytics

la = azloganalytics.LogAnalytics(config.azID, config.azSecret, "shadowserver")  # Create log analytics object with creds & table

subnets=True

def genHMAC(secret, request):  # Generate SHA256 HMAC from request & secret
    request_string = json.dumps(request)
    secret_bytes = bytes(str(secret), 'utf-8')
    request_bytes = bytes(request_string, 'utf-8')
    hmac_generator = hmac.new(secret_bytes, request_bytes, hashlib.sha256)
    hmac2 = hmac_generator.hexdigest()
    return hmac2


def listReports():  # Get list of available reports
    req = {"id": "", "limit": 100, "apikey": f"{config.key}"}
    url = 'https://transform.shadowserver.org/api2/reports/list'
    resp = requests.post(url, json=req, headers={"HMAC2": genHMAC(secret=config.secret, request=req)})
    return resp.json()


def downloadReport(reportID):  # Retreive data from specified report
    req = {"id": reportID, "limit": 5000, "apikey": f"{config.key}"}
    url = 'https://transform.shadowserver.org/api2/reports/download'
    resp = requests.post(url, json=req, headers={"HMAC2": genHMAC(secret=config.secret, request=req)})
    return resp.json()
 
def initIPAM()
    global subnets
    url='https://ipam.node4.co.uk/api/securityteam/sections/3/subnets/'
    authheader={'phpipam-token':config.ipamToken} 
    subnets=requests.get(url,headers=authheader).json()['data']
    print("IPAM Data downloaded...")

def getDescription(ip) 
    myIPAddress=ipaddress.ip_address(ip)
    matchingSubnets = [i for i in subnets if myIPAddress in ipaddress.ip_network(i['subnet']+'/'+i['mask'])]
    smallestSubnet = sorted(matchingSubnets, reverse=True, key=lambda d: d['mask'])[0]
    return smallestSubnet['description']

initIPAM()

for report in listReports():
    if report['type'] != "device_id":
        reportContent = downloadReport(report['id'])
        print(f"Report: {report['type']} - Records: {len(reportContent)}")
        if len(reportContent) == 5000:
            print("** LIMIT REACHED - Results Truncated")
        for device in reportContent:
            if "ip" in device:
                device['scan'] = report['type']
                device['subnet_description'] = getDescription(device['ip'])
                deviceJSON = []
                deviceJSON.append(device)
                la.sendtoAzure(deviceJSON)

