import requests
import time
import hashlib
from datetime import datetime

API        = "http://localhost:5000/ingest-log"
SECRET_KEY = "pentastic_secret"

# Edit these to simulate different users/scenarios
LOGS = [
    {
        "username":        "employee_1",
        "ip_address":      "192.168.1.23",
        "device":          "Office Laptop",
        "folder_accessed": "normal_folder"
    },
    {
        "username":        "attacker",
        "ip_address":      "8.8.8.8",
        "device":          "unknown",
        "folder_accessed": "Sensitive_Files"
    },
]

for log in LOGS:
    timestamp  = str(int(time.time()))
    login_time = datetime.now().strftime("%H:%M")

    data = {
        **log,
        "login_time": login_time,
        "timestamp":  timestamp
    }

    message   = f"{data['username']}{timestamp}{SECRET_KEY}"
    signature = hashlib.sha256(message.encode()).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-Signature":  signature
    }

    try:
        response = requests.post(API, json=data, headers=headers)
        print(f"[{log['username']}] → {response.json()}")
    except Exception as e:
        print(f"Error: {e}")

    time.sleep(1)