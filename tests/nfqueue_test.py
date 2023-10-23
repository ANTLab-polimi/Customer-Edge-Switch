#!/usr/bin/python3
# the link to the offical documentation
# https://pypi.org/project/NetfilterQueue/

"""
    This uses scapy to modify packets going through your machine in order to inject a NSH header
    to allow the TCP connection to be accepted by our switch in the outside MEC network.
    Based on nfqueue to block packets in the kernel and pass them to scapy for validation
"""

from netfilterqueue import NetfilterQueue
from scapy.all import *
from scapy.contrib.nsh import *
from json import JSONEncoder
import hmac, hashlib, base64, random
import binascii
import os

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
    

# [["192.168.1.1", 54321], ..., ["192.168.3.4", 3421]]
list_of_client = []

# iptables parameters
chain = "OUTPUT"
#interface = "enp3s0"
ip_dest = "192.168.2.2"
dport = "80"
protocol = "TCP"

# auth object parameters
http_port = 80
self_ip = "192.168.1.1"
method = "ip"
imsi = "310170845466094"
count = 1 # the starting value for the creation of a HMAC
version = 1.0 #the actual version of the HMAC process
master_key = ""

iptablesr = "iptables -A " + chain + " -d " + ip_dest + " -p " + protocol + " --dport " + dport + " -j NFQUEUE --queue-num 1"

print("Adding iptable rules :")
print(iptablesr)
# to be commented if you have already inserted the rule in the iptables
#os.system(iptablesr)

def isPresent(ip_address, sport):
    
    result = False

    for j in list_of_client:
        if j[0] == ip_address and j[1] == sport:
            result = True
            break       

    return result

def my_callback(payload):
    # Here is where the magic happens.
    data = payload.get_payload()
    pkt = IP(data)
    print("Got a packet ! source ip : " + str(pkt.src))

    # if the packet traffic is that one we are looking for, we are required to inject the header with the HMAC hash
    if pkt.dst == ip_dest and pkt.dport == 80 and not isPresent(pkt.src, pkt.sport):
        
        print("TCP connection to our service detected!")
        print("Here we need to insert the NSH header and forward the packet...")
        
        # tracking the new client avoiding to insert the NSH in the next packet immediatly
        new_client = [pkt.src,pkt.sport]
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

        # creating the header including the shake_128 hash
        new_pkt = NSH(mdtype=1, nextproto=1, context_header=my_hash)/pkt

        # https://stackoverflow.com/questions/42765084/python-script-used-to-modify-tcp-packets-using-nfqueue-and-scapy
        # this is better and more recent https://www.codetd.com/en/article/12988510
        # modifying the payload of the packet arrived and accepting it
        payload.set_payload(bytes(new_pkt))
        payload.accept()

        # another possible solution is a work around exploiting the sendp() scapy function
        # you need to drop the packet with a payload.drop()
        # then you are required to copy the previous payload, modify it and then send it

    else:
        # accept the packets in any case
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