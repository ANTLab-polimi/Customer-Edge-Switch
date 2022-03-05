import socket
import sys

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
sock.bind(("45.45.0.2", 1298)) #bind oaitun_ue1 iface to port 1298
server_address = ('192.169.56.2', 80)
sock.connect(server_address)