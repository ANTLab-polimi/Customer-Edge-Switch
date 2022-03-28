import socket
import sys
import time
#import tqdm
import os

HOST = "0.0.0.0"
PORT = 80  # Port to listen on (non-privileged ports are > 1023)
SIZE = 1024
FORMAT = "utf-8"

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.bind((HOST, PORT))
socket.listen()
while True:
    conn, client_address = socket.accept()
    with conn:
        while True:
            print("Connected at: " + str(time.time()))
            
            #Receiving the filename from the client
            filename = conn.recv(SIZE).decode(FORMAT)
            print(f"[RECV] Receiving the filename.")
            file = open(filename, "w")
            
            #Receiving the file data from the client
            data = conn.recv(SIZE).decode(FORMAT)
            print(f"[RECV] Receiving the file data.")
            file.write(data)
            
            #Closing the file
            file.close()
            print("File received at: " + str(time.time()))