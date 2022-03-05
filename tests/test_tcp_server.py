import socket
import sys

HOST = "0.0.0.0"
PORT = 80  # Port to listen on (non-privileged ports are > 1023)

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.bind((HOST, PORT))
socket.listen(1)
while True:
    connection, client_address = socket.accept()
    with connection:
        message = "Hello world!"
        print(f"Connected by {client_address}")
        socket.sendall(message)
        #while True:
        #    data = conn.recv(1024)
        #    if not data:
        #        break
        #    conn.sendall(data)