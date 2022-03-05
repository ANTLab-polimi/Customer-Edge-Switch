from scapy.all import *
import time
import requests
from diffie_hellman_ue import dh
import json
from json import JSONEncoder
import hmac, hashlib, base64

controller_ip = '192.168.56.2'
BCAST_MAC = "ff:ff:ff:ff:ff:ff"
SELF_MAC = "08:00:27:43:af:40"
self_ip = "192.168.56.1"

packet = Ether(dst = BCAST_MAC, src = SELF_MAC, type = 0x0806)/ARP(psrc = self_ip, hwsrc = SELF_MAC, pdst = controller_ip)