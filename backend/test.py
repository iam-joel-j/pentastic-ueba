import requests

data = {
    "username": "test_user",
    "login_time": "22:00",
    "ip_address": "10.10.10.5",
    "device": "Personal Laptop",
    "folder_accessed": "Decoy_Files"
}

response = requests.post(
    "http://localhost:5000/ingest-log",
    json=data
)

print(response.json())
