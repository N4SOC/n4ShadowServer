import config
import requests
import json
import hmac
import hashlib
import ipaddress
import threading

import azloganalytics

la = azloganalytics.LogAnalytics(config.azID, config.azSecret, "shadowserver")  # Create log analytics object with creds & table


def genHMAC(secret, request):  # Generate SHA256 HMAC from request & secret
    request_string = json.dumps(request)
    secret_bytes = bytes(str(secret), "utf-8")
    request_bytes = bytes(request_string, "utf-8")
    hmac_generator = hmac.new(secret_bytes, request_bytes, hashlib.sha256)
    return hmac_generator.hexdigest()


def listReports():  # Get list of available reports
    req = {"id": "", "limit": 100, "date": "2023-10-16", "apikey": f"{config.key}"}
    url = "https://transform.shadowserver.org/api2/reports/list"
    resp = requests.post(url, json=req, headers={"HMAC2": genHMAC(secret=config.secret, request=req)})
    return resp.json()


def downloadReport(reportID):  # Retreive data from specified report
    req = {"id": reportID, "limit": 10000, "apikey": f"{config.key}"}
    url = "https://transform.shadowserver.org/api2/reports/download"
    resp = requests.post(url, json=req, headers={"HMAC2": genHMAC(secret=config.secret, request=req)})
    print(f"Downloaded Report: {reportID} | {len(resp.json())}")
    return resp.json()


def initIPAM():
    global subnets
    url = "https://ipam.node4.co.uk/api/securityteam/sections/3/subnets/"
    authheader = {"phpipam-token": config.ipamToken}
    subnets = requests.get(url, headers=authheader).json()["data"]
    print("IPAM Data downloaded...")


def getDescription(ip):
    if "/" in ip:
        myIPAddress = ipaddress.IPv4Network(ip)
    else:
        myIPAddress = ipaddress.ip_address(ip)
    matchingSubnets = [i for i in subnets if myIPAddress in ipaddress.ip_network(i["subnet"] + "/" + i["mask"])]
    try:
        smallestSubnet = sorted(matchingSubnets, reverse=True, key=lambda d: d["mask"])[0]
    except:
        smallestSubnet = {"description": "not found"}
    return smallestSubnet["description"]


def sendRecord(scandata, scanType):
    scandata["scan"] = scanType
    scandata["subnet_description"] = getDescription(scandata["ip"])
    deviceJSON = []
    deviceJSON.append(scandata)
    la.sendtoAzure(deviceJSON)


def getScanData(scan):
    print("-------------")
    if report["type"] != "device_id":
        print(f"Start Report | {report['type']} | {report['file']} | {report['id']} ")
        reportContent = downloadReport(report["id"])
        print(f"Processing Report | {report['type']} | Records: {len(reportContent)}")
        if len(reportContent) == 10000:
            print("** 10k LIMIT REACHED - Results Truncated")
        for device in reportContent:
            if "ip" in device:
                t = threading.Thread(target=sendRecord, args=(device, report["type"]))
                threads.append(t)
                t.start()
        for t in threads:
            t.join()
    print("-------------")


threads = []
try:
    initIPAM()
except:
    print("Cannot reach IPAM")
    subnets = True


reportList = listReports()
print(f"Found {len(reportList)} scans")

for report in reportList:
    getScanData(report)
