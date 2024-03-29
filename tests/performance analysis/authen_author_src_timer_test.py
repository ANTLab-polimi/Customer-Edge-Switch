from scapy.all import *
import time
from diffie_hellman_ue import dh
import json
from json import JSONEncoder
import hmac, hashlib, base64
import socket
import os
import argparse
from send_file import send

def netcat(hostname, port, content, flag):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if flag:
        s.bind(("45.45.0.2", source_port))
        print("AUTH AT: " + str(time.time()))
    else:
        print("CONN AT: " + str(time.time()))
    s.connect((hostname, port))
    if flag:
        s.send(content)
        s.close()
    else:
        send(s)

controller_ip = '192.168.56.2'
self_ip = "45.45.0.2"
iface = 'oaitun_ue1'
auth_port = 101
source_port = 90 #used to specify source iface

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

#111111111111111 -> imsi for testing purpose
auth = Auth("192.169.56.2", "imsi", "111111111111111", 80, "TCP", "111111111111111", 1, 1.0)
#auth = Auth("192.169.56.2", "imsi", "111111111111111", 80, "TCP", "111111111111111", 1, 1.0)
#auth = Auth("192.169.56.2", "token", "abcdefghilmnopqrstuvz", 80, "TCP", "111111111111111", 1, 1.0)
auth = MyEncoder().encode(auth)
key = dh("111111111111111")
message_bytes = auth.encode('ascii')
base64_bytes = base64.b64encode(message_bytes)
hmac_hex = hmac.new(bytes(key, 'utf-8'), base64_bytes, hashlib.sha512).hexdigest()
msg = str(base64_bytes) + '---' + str(hmac_hex)
netcat("192.168.56.2", auth_port, bytes(msg, 'utf-8'), True)
time.sleep(0.1)
netcat("192.169.56.2", 80, b"ciao", False)