import requests

r = requests.get("https://localhost:7252", verify='root.pem')
print(r.status_code)
