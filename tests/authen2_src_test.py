#!/usr/bin/python3
from scapy.all import *
from scapy.contrib.nsh import *
import time
import json
from json import JSONEncoder
import hmac, hashlib, base64, random
from scapy_TCPSession import *
import subprocess
import os
import binascii

def netcat(hostname, port, content, flag):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, port))
    if flag:
        print("AUTH AT: " + str(time.time()))
        s.send(content)
        s.close()
    else:
        print("CONN AT: " + str(time.time()))

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
'''
    It's a simple test: with dh() we start the diffie-hellman key exchange, then we generate the HMAC and send it to the controller.
    Therefore, we open a simple client socket to comunicate with the server
'''
def src_test():

    # here we need to read from the file the key exchanged
    controller_ip = '192.168.56.2'
    # self_ip is the ip of the vm hydrogen because the 5G tunnel is not working for the moment
    self_ip = "192.168.56.1"
    dst_ip = "192.168.56.6"
    iface = 'eth0'
    key_port = 100
    http_port = 80
    protocol = "TCP"
    method = "ip"
    # random.seed(int(time.time()))
    #imsi = ranodm.randint( int(pow(1,pow(10,15))) , int(pow(9.0,pow(10,15))) )
    #imsi = random.randint(100000000000000,999999999999999)
    imsi = "310170845466094"
    #print(imsi)
    count = 1
    version = 1.0
    master_key = ""

    start_hash = time.time()
    print("STARTING HASH AT " + str(start_hash))

    # reading the master_key

    name_file = str(imsi) + "master_key.txt"
    fd = open(name_file, 'r')
    try:
        # or read(16)
        master_key = fd.readline()
    finally:
        fd.close()

    print("master_key: " + master_key)

    # starting the authorization phase, encoding the message and hmac with the dh key

    auth = Auth(dst_ip, method, self_ip, http_port, protocol, imsi, count, version)
    #auth = Auth("192.169.56.2", "imsi", "111111111111111", 80, "TCP", "111111111111111", 1, 1.0)
    #auth = Auth("192.169.56.2", "token", "abcdefghilmnopqrstuvz", 80, "TCP", "111111111111111", 1, 1.0)
    auth = MyEncoder().encode(auth)
    message_bytes = auth.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)

    # the previous hmac but it was based on 512 bits...too long
    #hmac_hex = hmac.new(bytes(key, 'utf-8'), base64_bytes, hashlib.sha512).hexdigest()

    # shake_128 asserts collision resistance on 64 bits so for the 8 hexdigest we are ok ->
    # in the NSH we can insert only 16 bytes...
    # To recreate an HMAC, we can concatenate an incremental counter, the master key and the hashed message
    # then apply the hash algorithm
    hash_hex = hashlib.shake_128(str(count).encode() + bytes(master_key, 'utf-8') + base64_bytes).hexdigest(16)
    
    # our special port (not one in common range)
    sport = 54321

    start_TCPSYN = time.time()
    print("SENDING TCP CONNECTION SYN AT " + str(start_TCPSYN))

    fake_socket = TcpSession(self_ip,dst_ip,sport,http_port)

    print("hash_hex: " + hash_hex)
    # to make executable the two shell script which HAVE TO BE ALREADY
    # PRESENT IT THE DIRECTORY
    #os.system('chmod +x disable_the_kernel_drop.sh')
    #os.system('chmod +x activate_the_kernel_drop.sh')
    # to temporary disable the RST tcp packet send from the kernel
    #subprocess.call(['sh','./disable_the_kernel_drop.sh'])

    # starting simulating the TCP userstack session
    my_hash = binascii.unhexlify(hash_hex)
    #print(my_hash)

    fake_socket.connect(my_hash)

    finish_TCPSYN = time.time()
    print("RECEIVING TCP CONNECTION SYN ACK AT " + str(finish_TCPSYN))
    print("TOTAL TIME threeway handshake TCP: " + str(finish_TCPSYN - start_TCPSYN))
    i = 0
    while i < 5:
        msg = 'HI FROM THE CLIENT! :D'
        fake_socket.send(msg)
        fake_socket.my_sniff()
        i = i + 1

    fake_socket.close()
    

    # to reactivate the eventually RST tcp packet send from the kernel
    #subprocess.call(['sh','./activate_the_kernel_drop.sh'])


if __name__ == "__main__":
    src_test()