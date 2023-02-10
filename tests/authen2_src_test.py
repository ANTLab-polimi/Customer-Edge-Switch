#!/usr/bin/python3
from scapy.all import *
from scapy.contrib.nsh import *
import time
from diffie_hellman_ue import dh
import json
from json import JSONEncoder
import hmac, hashlib, base64, random
from TCPSession.py import *
import subprocess
import os

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

    controller_ip = '192.168.56.2'
    # self_ip is the ip of the vm hydrogen because the 5G tunnel is not working for the moment
    self_ip = "192.168.56.1"
    dst_ip = "192.168.56.6"
    iface = 'eth0'
    auth_port = 101
    http_port = 80
    protocol = "TCP"
    method = "ip"
    #imsi = "302130123456789"
    random.seed(int(time.time()))
    #imsi = ranodm.randint( int(pow(1,pow(10,15))) , int(pow(9.0,pow(10,15))) )
    imsi = random.randint(100000000000000,999999999999999)
    print(imsi)
    count = 1
    version = 1.0

    # starting the authentication phase

    auth = Auth(dst_ip, method, self_ip, http_port, protocol, imsi, count, version)
    #auth = Auth("192.169.56.2", "imsi", "111111111111111", 80, "TCP", "111111111111111", 1, 1.0)
    #auth = Auth("192.169.56.2", "token", "abcdefghilmnopqrstuvz", 80, "TCP", "111111111111111", 1, 1.0)
    auth = MyEncoder().encode(auth)

    # key exchanging
    # TODO dh needs a parameterization for the IPs and ports...
    # TODO refactor the dh procedure, teoretically should exist an implementation already done...

    key = dh(imsi)

    # continuing the authentication phase, encoding the message and hmac with the dh key

    message_bytes = auth.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    hmac_hex = hmac.new(bytes(key, 'utf-8'), base64_bytes, hashlib.sha512).hexdigest()
    msg = str(base64_bytes) + '---' + str(hmac_hex)

    #TODO the next step is fusing the next two phases: HMAC sending + the message to the server
    sport = 54321
    fake_socket = TCPSession(self_ip,dst_ip,sport,http_port)

    nsh_addition = NSH(mdtype=2,nextproto=1,length=len(hmac_hex),metadata=hmac_hex)

    # to make executable the two shell script which HAVE TO BE ALREADY
    # PRESENT IT THE DIRECTORY
    os.system('chmod +x disable_the_kernel_drop.sh')
    os.system('chmod +x activate_the_kernel_drop.sh')
    # to temporary disable the RST tcp packet send from the kernel
    subprocess.call(['sh','./disable_the_kernel_drop.sh'])

    # TODO starting simulating the TCP userstack session

    fake_socket.connect(nsh_addition)

    msg = 'HI FROM THE CLIENT! :D'

    fake_socket.send(msg)

    fake_socket._sniff()

    fake_socket.close()


    #to reactivate the eventually RST tcp packet send from the kernel
    subprocess.call(['sh','./activate_the_kernel_drop.sh'])

    '''
    # sending the authentication message to the controller
    netcat(controller_ip, auth_port, bytes(msg, 'utf-8'), True)
    time.sleep(0.1)
    '''
    '''
    # open a socket to comunicate with the server:
    # THIS IS WORKING BUT I NEED TO UNDERSTAND HOW THE PACKET IS RECEIVED IN THE SDN ELEMENT
    # AND I'M TRYING TO RANDOMIZE THE IMSI SO I DON'T HAVE EVERYTIME RESTART THE ORCHESTRATOR EVERYTIME
    print("Requesting connection with server...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((dst_ip, http_port))
        ss = scapy.supersocket.SimpleSocket(s)
        print("CONNECT WITH SERVER")
        while True:
            time.sleep(2)
            msg = b'Hello from the client :D'
            x = scapy.contrib.nsh.NSH(msg)
            ss.send(x)
            print(x)
            data = ss.recv(1024)
            if not data:
                print("no data :(")
                break
            else:
                print(f"Received: {data!r}")
    except TimeoutError:
        print("TIMEOUT ERROR")
    except ConnectionRefusedError:
        print("CONNECTION REFUSED ERROR")
    finally:
        ss.close()
        print("Socket closed")
    '''


if __name__ == "__main__":
    src_test()