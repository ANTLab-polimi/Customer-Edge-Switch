# echo-client.py

import socket
import time

HOST = "192.168.2.2"  # The server's hostname or IP address
PORT = 80  # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    while (True):

        s.sendall(b"Hello, world")
        data = s.recv(1024)
        print(f"Received {data!r}")
        time.sleep(5)