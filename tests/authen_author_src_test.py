from scapy.all import *
import time
from diffie_hellman_ue import dh
import json
from json import JSONEncoder
import hmac, hashlib, base64
from send_file import send

controller_ip = '192.168.56.2'
self_ip = "192.187.3.254"
dst_ip = "192.168.56.6"
iface = 'eth0'
auth_port = 101
http_port = 80
protocol = "TCP"
method = "ip"

def netcat(hostname, port, content, flag):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, port))
    if flag:
        print("AUTH AT: " + str(time.time()))
        s.send(content)
        s.close()
    else:
        print("CONN AT: " + str(time.time()))
        send(s)

class Auth():

    def __init__(self, service_ip, method, authentication, port, protocol, imsi, count, version):
        self.service_ip = service_ip
        self.method = method
        self.authentication = authentication
        self.port = str(port)
        self.protocol = protocol
        self.imsi = imsi
        self.count = count
        self.version = version

class MyEncoder(JSONEncoder):
    def default(self, obj):
        return obj.__dict__

ismi = "302130123456789"
count = 1
version = 1.0

# starting the authentication phase

auth = Auth(dst_ip, method, self_ip, http_port, protocol, ismi, count, version)
#auth = Auth("192.169.56.2", "imsi", "111111111111111", 80, "TCP", "111111111111111", 1, 1.0)
#auth = Auth("192.169.56.2", "token", "abcdefghilmnopqrstuvz", 80, "TCP", "111111111111111", 1, 1.0)
auth = MyEncoder().encode(auth)

# key exchanging
# TODO dh needs a parameterization for the IPs and ports...

key = dh("302130123456789")

# continuing the authentication phase, encoding the message and hmac with the dh key

message_bytes = auth.encode('ascii')
base64_bytes = base64.b64encode(message_bytes)
hmac_hex = hmac.new(bytes(key, 'utf-8'), base64_bytes, hashlib.sha512).hexdigest()
msg = str(base64_bytes) + '---' + str(hmac_hex)

# sending the authentication message to the controller
netcat(controller_ip, auth_port, bytes(msg, 'utf-8'), True)
time.sleep(0.1)

# open a socket to comunicate with the server:

print("Requesting connection with server...")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((dst_ip, http_port))
i = 1
while True:
    time.sleep(1)
    s.senddall(b"Hello world!" + bytes(i))
    data = s.recv(1024)
    if not data:
        print("no data :(")
        break
    else:
        print(f"Received: {data!r}")
    i = i + 1

#netcat(dst_ip, http_port, b"Hello Helium!", False)