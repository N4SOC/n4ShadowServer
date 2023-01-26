import json
import requests
import datetime
import hashlib
import hmac
import base64

class LogAnalytics:
    def __init__(self, customer_id, shared_key, log_type):
        self.customer_id = customer_id
        self.shared_key = shared_key
        self.log_type = log_type

    # Build the API signature
    def build_signature(self,customer_id, shared_key, date, content_length, method, content_type, resource):
        x_headers = 'x-ms-date:' + date
        string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
        bytes_to_hash = bytes(string_to_hash, encoding="utf-8")  
        decoded_key = base64.b64decode(shared_key)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
        authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
        return authorization

    # Build and send a request to the POST API
    def post_data(self,customer_id, shared_key, body, log_type):
        method = 'POST'
        content_type = 'application/json'
        resource = '/api/logs'
        rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        content_length = len(json.dumps(body))
        signature = self.build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
        uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

        headers = {
            'content-type': content_type,
            'Authorization': signature,
            'Log-Type': log_type,
            'x-ms-date': rfc1123date
        }

        response = requests.post(uri,json=body, headers=headers)
        if (response.status_code >= 200 and response.status_code <= 299):
            print('Accepted')
        else:
            print("Response code: " + str(response.status_code) + ' ' + response.text)

    def sendtoAzure(self,data):
        body = data
        self.post_data(self.customer_id, self.shared_key, body, self.log_type)


