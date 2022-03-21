from scapy.all import *
import time
from diffie_hellman_ue import dh
import json
from json import JSONEncoder
import hmac, hashlib, base64
import threading

controller_ip = '192.168.56.2'
self_ip = "45.45.0.2"
iface = 'oaitun_ue1'
auth_port = 101

requests = []
amount_of_series = 10

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

def requests_generation(key):
    global requests
    for i in range(1, 100):
        auth = Auth("192.169.56." + str(i), "ip", "192.168.56.1", 80 + i, "TCP", "302130123456789", i, 1.0)
        auth = MyEncoder().encode(auth)
        message_bytes = auth.encode('ascii')
        base64_bytes = base64.b64encode(message_bytes)
        hmac_hex = hmac.new(bytes(key, 'utf-8'), base64_bytes, hashlib.sha512).hexdigest()
        msg = str(base64_bytes) + '---' + str(hmac_hex)

        packet = IP(dst=controller_ip, src=self_ip)/UDP(sport=1298, dport=auth_port)/msg
        requests.append(packet)


key = dh("302130123456789")

count = 0

while count < amount_of_series:
    
    def series_handling(key):
        global requests
        start_thread = time.time()
        requests_generation(key)
        count_pkt = 0
        for request in requests:
            sendp(request, iface=iface)
            count_pkt = count_pkt + 1
            print("# Packet sent: " + str(count_pkt))
        print("Total amount of time for handling " + str(count_pkt) + " requests is: " + str(time.time()-start_thread))

    start = time.time()
    series = threading.Thread(target = series_handling, args = (key,)).start()
    while time.time() - start < 30:
        "nothing"
    count = count + 1