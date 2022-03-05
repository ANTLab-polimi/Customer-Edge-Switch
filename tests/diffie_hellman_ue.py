import random
import hashlib
import sys
from scapy.all import *
import json
from json import JSONEncoder

controller_ip = '192.168.56.2'
self_ip = "45.45.0.2"
key = ''
key_port = 100
iface = "oaitun_ue1"

def isPrime(k):
    if k==2 or k==3: return True
    if k%2==0 or k<2: return False
    for i in range(3, int(k**0.5)+1, 2):
        if k%i==0:
            return False

    return True

class DH():

    def __init__(self, p, g, A, imsi, version):
        self.p = p
        self.g = g
        self.A = A
        self.imsi = imsi
        self.version = version

class MyEncoder(JSONEncoder):
    def default(self, obj):
        return obj.__dict__

#generates prime numbers
def dh(identity):
    minPrime = 0
    maxPrime = 1001
    cached_primes = [i for i in range(minPrime,maxPrime) if isPrime(i)]
    p = random.choice(cached_primes)
    g = random.randint(2, 100)
    a = random.randint(2, 100)
    A = (g**a) % p
    imsi = identity

    #[...] sends p, g, A to controller, waits for B
    dh = DH(p, g, A, imsi, 1.0)
    dh = MyEncoder().encode(dh)
    pkt = IP(src = self_ip, dst = controller_ip)/UDP(sport = 1298, dport = key_port)/str(dh)

    sendp(pkt, iface = iface)

    def key_computation(pkt):
        global key
        raw = str(pkt.getlayer(Raw)).split('\\')[0][2:]
        B = int(raw)
        key = hashlib.sha256(str((int(B)**int(a)) % int(p)).encode()).hexdigest()

    #waits for B
    packet = sniff(prn = lambda x:key_computation(x), count = 1, iface=iface, filter = 'src host 192.168.56.2 and src port 100')
    return key

#--- controller ---
#[...] receives p, g, A
#b=random.randint(10,20)
#B = (g**b) % p
#sends B to ue
#keyB = hashlib.sha256(str((A**b) % p).encode()).hexdigest()
#print(keyB)
#saves key for specific ue