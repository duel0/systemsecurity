import requests
import json

url = 'http://localhost:8080/xacml'
headers = {"Content-Type": "application/json"}
body = { 'role': 'admin', 'resource': 'http://localhost:1200/private/*', 'action': 'GET' }
json_body = json.dumps(body)
r = requests.post(url = url, headers=headers, data = json_body)
# extracting the response
print(r.text)