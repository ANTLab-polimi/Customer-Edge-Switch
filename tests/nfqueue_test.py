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
# [["192.168.1.1", 54321, "SYN"], ..., ["192.168.3.4", 3421, "SYN_ACK"]]
list_of_client = []

# iptables1 parameters
chain = "FORWARD"
iface = "enp3s0"
ip_dest = "192.168.2.2"
dport = "80"
protocol = "TCP"


# auth object parameters
http_port = 54321
self_ip = "192.168.1.1"
method = "ip"
imsi = "310170845466094"
count = 1 # the starting value for the creation of a HMAC
version = 1.0 #the actual version of the HMAC process
master_key = ""

#iptable_output = "iptables -A " + chain + " -d " + ip_dest + " -p " + protocol + " --dport " + dport + " -j NFQUEUE --queue-num 1"
iptable_forward = "iptables -I " + chain + " 1 " + " -d " + ip_dest + " -p " + protocol + " --dport " + dport + " -o " + iface + " -j NFQUEUE --queue-num 1"

print("Adding iptable rules:")
#print(iptable_output)
print(iptable_forward)

# to be commented if you have already inserted the rule in the iptables
#os.system(iptable_output)
#os.system(iptable_forward)

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
        

def my_callback(payload):
    # Here is where the magic happens.
    data = payload.get_payload()
    pkt = IP(data)
    print("Got a packet ! source ip : " + str(pkt.src))
    print(pkt.dst, ip_dest)
    print(pkt.dport, dport)
    print(pkt[TCP].flags)
    """
        The flags of the TCP connection (here the first 5 are relevant):

        FIN = 0x01  00000001    to tear down the connection (it has to be sent by each of the entities)
        SYN = 0x02  00000010    to start the three-way handshake connection
        RST = 0x04  00000100    to signal that the connection is down or the service is not accepting the requests
        PSH = 0x08  00001000    to signal a packet which is pushing some data to the application directly
        ACK = 0x10  00010000    to ack a packet previously received, to confirm the initiation and/or tear down requests
        URG = 0x20  00100000    to indicate that the data should be processeed immediatly by the TCP stack (used also to provide out-of-band data)
        ECE = 0x40  01000000    (ECN-Echo) if SYN flag on, the TCP peer is Explicit Congestion Notification capable. Else a CEN packet is received normally
        CWR = 0x80  10000000    (Congestion Window Reduced) to signal that the previous packet received was a ECE one
    """

    # if the packet traffic is that one we are looking for, we are required to inject the header with the HMAC hash
    # it has to be the first packet
    if pkt.dst == ip_dest and pkt.dport == 80 and (pkt[TCP].flags & 0x2 == 0x2) and not(pkt[TCP].flags & 0x12 == 0x12):
        
        print("TCP connection to our service detected!")
        print("Here we need to insert the NSH header and forward the packet...")

        if not isPresent(pkt.src, pkt.sport):
            new_client = [pkt.src,pkt.sport, "SYN"]
            list_of_client.append(new_client)
            print(list_of_client)
        
        # reading the master_key retrieved by the previous key exchange phase
        print("Reading the master key")
        name_file = str(imsi) + "master_key.txt"
        fd = open(name_file, 'r')
        try:
            # or read(16)
            master_key = fd.readline()
        finally:
            fd.close()

        # auth object creation
        auth = Auth(ip_dest, method, self_ip, http_port, protocol, imsi, count, version)
        # dictionary encoding
        auth = MyEncoder().encode(auth)
        message_bytes = auth.encode('ascii')
        base64_bytes = base64.b64encode(message_bytes)

        # shake_128 hash function to create a HMAC exploiting the collision resistance propriety
        hash_hex = hashlib.shake_128(str(count).encode() + bytes(master_key, 'utf-8') + base64_bytes).hexdigest(16)
        my_hash = binascii.unhexlify(hash_hex)
        #print(my_hash)

        # creating the header including the shake_128 hash
        # using the deepcopy in order to do not have in common anything with the original packet
        # on which nfqueue can act
        my_pkt = copy.deepcopy(pkt)
        new_pkt = NSH(mdtype=1, nextproto=1, context_header=my_hash)/my_pkt
        new_pkt[IP].src = "192.168.1.1"

        del new_pkt[IP].chksum
        del new_pkt[TCP].chksum

        new_pkt.show2(dump=True)

        # https://www.codetd.com/en/article/12988510 + https://pypi.org/project/NetfilterQueue/#limitations
        # nfqueue is cutting every modification under the third layer including our manipulation under the IP layer
        # so we need to drop the packet retrieved from the iptables
        payload.drop()
        
        mac_address_destination = "ff:ff:ff:ff:ff:ff" # broadcast
        #mac_address_destination = "50:3e:aa:11:5b:ce" # this is the specific MAC address of the first iface of the central machine
        #mac_address_destination = "6c:4b:90:dd:27:87" # this is the specific MAC address of the final machine
        # but it should not be set because in a real context you should not know the server MAC address...
        
        # forging the packet to be sent
        pkt_to_send = Ether(dst=mac_address_destination)/new_pkt
        #print(pkt_to_send)
        
        # We are sending the packet with the sendp built-in function of scapy forcing the packet out through
        # the interface that we want 
        scapy.sendrecv.sendp(pkt_to_send, iface=iface)
        

    else:
        # SYN ACK packet of the TCP connection
        if pkt.dst == ip_dest and pkt.dport == 80 and (pkt[TCP].flags & 0x12 == 0x12):
            # tracking the new client avoiding to insert the NSH in the next packet immediatly
            update_connection(pkt.src, pkt.sport, "SYN_ACK") 
            print(list_of_client)
        
        # accept the packets in any case modifying the IP address
        my_pkt2 = copy.deepcopy(pkt)
        my_pkt2[IP].src = "192.168.1.1"

        del my_pkt2[IP].chksum
        del my_pkt2[TCP].chksum

        my_pkt2.show2(dump=True)
        payload.set_payload(bytes(my_pkt2))
        payload.accept()


def main():
    # This is the net filter queue object
    nfqueue = NetfilterQueue()

    # "bind" create the queue, set its callback function
    # and attach it to the iptables with the id set before
    nfqueue.bind(1, my_callback)

    try:
        nfqueue.run() # Main loop, it starts the callback function
    except KeyboardInterrupt:
        print("KeyboardInterrupt...\n")
        print("REMEMBER TO FLUSH IPTABLES MANUALLY...")
        # This flushes everything, you might wanna be careful
        #os.system('iptables -F')
        #os.system('iptables -X')

    # unbind in any case
    nfqueue.unbind()

if __name__ == "__main__":
    main()
