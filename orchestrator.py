import grpc
import os
import sys
import p4runtime_sh.shell as sh
from p4runtime_sh.shell import PacketIn
from time import sleep
from scapy.all import *
import yaml
import threading

# No need to import p4runtime_lib
# import p4runtime_lib.bmv2

#check if PolicyDB has been modified
def mod_detecter():
    while True:
        i = inotify.adapters.Inotify()
        i.add_watch("policiesDB.yaml")

        for event in i.event_gen(yield_nones=False):
            (_, type_names, path, filename) = event

            if "IN_CLOSE_WRITE" in event[1]: #type_names is a list
                print("[!] POLICYDB MODIFIED")
                #[!] to add -> function that manages modifications in policyDB

            #log:
            #print("PATH=[{}] FILENAME=[{}] EVENT_TYPES={}".format(path, filename, type_names))



def checkPolicies(pkt):
    #policyDB as a yaml file
    #each policy is a tuple containing specific attributes
    stream = open("policiesDB.yaml", 'r')
    policies_list = yaml.safe_load(stream)
    
    policies_len = le

    lookForPolicy(policies_list, pkt)

    #if policyDB is a .txt file
    #policies = []
    #with open("policiesDB.txt", 'r') as f:
    #    print("policiesDB.txt opened")
    #    line = f.readline()
    #    while line:
    #        policies.append(line.split(" "))
    #        line = f.readline()


#if policyDB is managed as a true db
def checkPoliciesDB(packet):
    policies = []
    try:
        with connect(
            host="localhost",
            user=input("Enter your username: "),
            password=input("Enter your password: "),
            database="PolicyDB"
        ) as connection:
            print(connection)
            prepared_statement = "SELECT * FROM policies"
            with connection.cursor() as cursor:
                cursor.execute(prepared_statement)
                policies = cursor.fetchall()
            print(policies)
            lookForPolicy(policies, packet)

    except Error as e:
        print(e)


def lookForPolicy(policyList, pkt):
    found = False
    print("[!] Policies: \n")
    print(policyList)
    
    src = pkt.getlayer(IP).src
    dst = pkt.getlayer(IP).dst
    
    pkt_tcp = pkt.getlayer(TCP)
    pkt_udp = pkt.getlayer(UDP)
    protocol = ""
    if pkt_tcp != None:
        sport = pkt_tcp.sport
        dport = pkt_tcp.dport
        protocol = "TCP"
    elif pkt_udp != None:
        sport = pkt_udp.sport
        dport = pkt_udp.dport
        protocol = "UDP"
    else:
        print("\n[!] Protocol unknown\n")
        return

    print("src: " + src)
    print("dst: " + dst)
    print("sport: " + str(sport))
    print("dport: " + str(dport))
    

    pkt_icmp = pkt.getlayer(ICMP)
    pkt_ip = pkt.getlayer(IP)

    for policy in policyList:
        #policy_tuple.get("dst")
        if src == policy.get("src") and dst == policy.get("ip") and dport == policy.get("port") and protocol == policy.get("protocol"): #check how to specify src (imsi, ip, ...)
            addEntries(src, dst, dport)
            
            #add bi-directional entry if icmp packet
            if pkt_icmp != None and pkt_ip != None and str(pkt_icmp.getlayer(ICMP).type) == "8":
                addEntries(dst, src, sport)
            
            found = True
            break
    if not found:
        #packet drop
        packet = None
        print("[!] Packet dropped\n\n\n")

def addEntries(ip_src, ip_dst, port):
    te = sh.TableEntry('my_ingress.ipv4_exact')(action='my_ingress.ipv4_forward')
    te.match["hdr.ipv4.srcAddr"] = ip_src
    te.match["hdr.ipv4.dstAddr"] = ip_dst
    te.action["port"] = port
    te.insert()
    print("[!] New entry added\n\n\n")


def packetHandler(streamMessageResponse):
    print("[!] Packets received")
    packet = streamMessageResponse.packet

    if streamMessageResponse.WhichOneof('update') =='packet':
        packet_payload = packet.payload
        pkt = Ether(_pkt=packet.payload)
        
        if pkt.getlayer(IP) != None:
            pkt_src = pkt.getlayer(IP).src
            pkt_dst = pkt.getlayer(IP).dst
        ether_type = pkt.getlayer(Ether).type
        pkt_icmp = pkt.getlayer(ICMP)
        pkt_ip = pkt.getlayer(IP)

        if pkt_icmp != None and pkt_ip != None and str(pkt_icmp.getlayer(ICMP).type) == "8":
            print("[!] Ping from: " + pkt_src)
            checkPolicies(pkt)
        elif pkt_ip != None:
            print("[!] Packet received: " + pkt_src + "-->" + pkt_dst)
            checkPolicies(pkt)
        else:
            print("[!] No needed layer (ARP, DNS, ...)")

def controller():
    #connection
    sh.setup(
        device_id=0,
        grpc_addr='192.187.3.8:50051', #substitute ip and port with the ones of the specific switch
        election_id=(1, 0), # (high, low)
        config=sh.FwdPipeConfig('p4-test.p4info.txt','p4-test.json')
    )

    detector = threading.Thread(target = mod_detecter)
    detector.start()

    while True:
        packets = None
        print("Waiting for receive something")
        packet_in = sh.PacketIn()
        packets = packet_in.sniff(timeout=5)
        for streamMessageResponse in packets:
            packetHandler(streamMessageResponse)

if __name__ == '__main__':
    controller()