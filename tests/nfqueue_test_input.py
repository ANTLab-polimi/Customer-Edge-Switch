#!/usr/bin/python3
# the link to the offical documentation
# https://pypi.org/project/NetfilterQueue/

"""
    This uses scapy to modify packets going through your machine in order to inject a NSH header
    to allow the TCP connection to be accepted by our switch in the outside MEC network.
    Based on nfqueue to block packets in the kernel and pass them to scapy for validation.
    (it is not tracking the entire state of the connection, just the three-way handshake TCP connection)
"""

from netfilterqueue import NetfilterQueue
from scapy.all import *
from scapy.contrib.nsh import *
from json import JSONEncoder
import hmac, hashlib, base64, random
import binascii
import os
import copy

# this allows us to group the multiple variables to create a HMAC
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
    This data structure is articulated as a list which contains entities like this one:
    ["ip_address", port_number, a_string_indentifing_the_status_of_the_connection]
    the various status are:
    SYN
    ACK
    SYN_ACK
    OK
    in practice, we are handling JUST the three-way handshake TCP connection
'''
# [["192.168.1.1", 54321, "SYN"], ..., ["192.168.3.4", 3421, "OK"]]
list_of_client = []

# iptables_input parameters
chain = "INPUT"
iface = "enp3s0"
ip_dest = "192.168.2.2"
sport = "80"
protocol = "TCP"
upf_ip = "192.187.3.6"
self_ip = "192.168.1.1"
upf_iface = "vethf37ebbe"

iptable_input = "iptables -I " + chain + " 1" + " -s " + ip_dest + " -d " + self_ip + " -p " + protocol + " --sport " + sport + " -i " + iface + " -j NFQUEUE --queue-num 2"


print("Adding iptable rules:")
print(iptable_input)

# to be commented if you have already inserted the rule in the iptables
#os.system(iptable_input)

def isPresent(ip_address, sport):
    
    result = False

    for j in list_of_client:
        if j[0] == ip_address and j[1] == sport:
            result = True
            break       

    return result

def update_connection(ip_address, sport, new_flag):

    for j in list_of_client:
        if j[0] == ip_address and j[1] == sport:
            j[2] = new_flag
            break
        

def my_second_callback(payload):

    data = payload.get_payload()
    pkt = IP(data)
    print("Got a packet ! source ip : " + str(pkt.src))

    if pkt.src == ip_dest and pkt.sport == 80 and (pkt[TCP].flags & 0x10 == 0x10):
        if pkt.dst == "192.168.1.1":
            new_pkt = copy.deepcopy(pkt)
            new_pkt[IP].dst = "192.187.3.6"

            del new_pkt[IP].chksum
            del new_pkt[TCP].chksum

            new_pkt.show2(dump=True)

            payload.drop()

            mac_address_destination = "ff:ff:ff:ff:ff:ff" # broadcast
            #mac_address_destination = "50:3e:aa:11:5b:ce" # this is the specific MAC address of the final machine
            # but it should not be set because in a real context you should not know the server MAC address...
            
            # forging the packet to be sent
            pkt_to_send = Ether(dst=mac_address_destination)/new_pkt
            #print(pkt_to_send)
            
            # We are sending the packet with the sendp built-in function of scapy forcing the packet out through
            # the interface that we want 
            scapy.sendrecv.sendp(pkt_to_send, iface=upf_iface)

    else: # accept payload in any case
        payload.accept()

def main():
    # This is the net filter queue object
    nfqueue_input = NetfilterQueue()

    # "bind" create the queue, set its callback function
    # and attach it to the iptables with the id set before
    nfqueue_input.bind(2, my_second_callback)

    try:
        nfqueue_input.run() # Main loop, it starts the callback function
    except KeyboardInterrupt:
        print("KeyboardInterrupt...\n")
        print("REMEMBER TO FLUSH IPTABLES MANUALLY...")
        # This flushes everything, you might wanna be careful
        #os.system('iptables -F')
        #os.system('iptables -X')

    # unbind in any case
    nfqueue_input.unbind()

if __name__ == "__main__":
    main()
