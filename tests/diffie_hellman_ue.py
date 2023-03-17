import random
import hashlib
import sys
from scapy.all import *
import json
from json import JSONEncoder
import socket
import os


def isPrime(k):
    if k==2 or k==3: return True
    if k%2==0 or k<2: return False
    for i in range(3, int(k**0.5)+1, 2):
        if k%i==0:
            return False

    return True

def netcat(hostname, port, content, a, p):
    key = ""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, port))
    s.send(content)
    time.sleep(0.1)
    while 1:
        data = s.recv(1024)

        def key_computation(pkt):
            raw = str(data).split('\\')[0][2:]
            B = int(raw[:-1])
            key = hashlib.sha256(str((int(B)**int(a)) % int(p)).encode()).hexdigest()
            return key

        if len(data) == 0:
            "nothing"
        else:
            key = key_computation(data)
            print("DH FINISHED AT: " + str(time.time()))
            break

    s.close()
    return key

# Auth(dst_ip, method, self_ip, http_port, protocol, imsi, count, version)
class DH():

    def __init__(self, p, g, A, imsi, version, service_name):
        self.p = p
        self.g = g
        self.A = A
        self.imsi = imsi
        self.version = version
        self.service_name = service_name

class MyEncoder(JSONEncoder):
    def default(self, obj):
        return obj.__dict__

#generates prime numbers
def dh(identity,controller_ip,key_port, service_name):
    minPrime = 0
    maxPrime = 1001
    cached_primes = [i for i in range(minPrime,maxPrime) if isPrime(i)]
    p = random.choice(cached_primes)
    g = random.randint(2, 100)
    a = random.randint(2, 100)
    A = (g**a) % p
    imsi = identity

    #[...] sends p, g, A to controller, waits for B
    dh = DH(p, g, A, imsi, 1.0, service_name)
    dh = MyEncoder().encode(dh)
    key2 = netcat(controller_ip, key_port, bytes(dh, 'utf-8'), a, p)

    return key2



def key_exchange():
    self_ip = "192.168.56.1"
    controller_ip = "192.168.56.2"
    key = ''
    key_port = 100
    #source_port = 91 #used to specify source iface
    iface = "eth0"
    imsi = "310170845466094"
    service_name = "serviceName"
    master_key = ""


    master_key = dh(imsi, controller_ip, key_port, service_name)
    print("master_key: " + master_key)
    if master_key == -1:
        print("something was wrong...")
    else:
        # writing the master key in a file:
        name_file = str(imsi) + 'master_key.txt'
        fd = open(name_file, 'w')
        os.system('chmod +r ' + name_file)
        os.system('chmod +w ' + name_file)
        try:
            fd.write(master_key)
        finally:
            fd.close()

if __name__ == '__main__':
    key_exchange()

#--- controller ---
#[...] receives p, g, A
#b=random.randint(10,20)
#B = (g**b) % p
#sends B to ue
#keyB = hashlib.sha256(str((A**b) % p).encode()).hexdigest()
#print(keyB)
#saves key for specific ue