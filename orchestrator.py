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


policies_list = []

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


#find out specific modifications per policy
#[!] TOADD: ip management when auth \wo ip
def mod_manager():
    global policies_list
    tmp = policies_list
    getPolicies()
    
    found = False

    for policy_tmp in tmp:

        for policy in policies_list:
            if policy.get("serviceName") == policy_tmp.get("serviceName"):
                found = True
                
                if policy.get("ip") != policy_tmp.get("ip"):
                    print("[!] IP_MODIFICATIONS")
                    print("[!] Editing policies IP...")
                    editIPPolicies(policy_tmp.get("ip"), policy.get("ip"), policy.get("port"))
        
                if policy.get("port") != policy_tmp.get("port"):
                    print("[!] PORT_MODIFICATIONS")
                    print("[!] Editing policies Port...")
                    editPortPolicies(policy_tmp.get("ip"), policy_tmp.get("port"))

                if policy.get("protocol") != policy_tmp.get("protocol"):
                    print("[!] PROTOCOL_MODIFICATIONS")
                    
                #UE checks (add or del)
                for ue in policy.get("allowed_users"):
                    if ue not in policy_tmp.get("allowed_users"):
                        print("[!] UE_MODIFICATIONS_ADD")
                        addEntries(ue_ip, policy.get("ip"), policy.get("port")) #[!] how to handle ue_ip \w auth different from ip?
                for ue in policy_tmp.get("allowed_users"):
                    if ue not in policy.get("allowed_users"):
                        print("[!] UE_MODIFICATIONS_DEL")
                        delUE(ue_ip, policy.get("ip")) #[!] how to handle ue_ip \w auth different from ip?

                if policy.get("tee") != policy_tmp.get("tee"):
                    print("[!] TEE_MODIFICATIONS")
                    
                if policy.get("fs_encr") != policy_tmp.get("fs_encr"):
                    print("[!] FS_ENCR_MODIFICATIONS")
                    
                if policy.get("net_encr") != policy_tmp.get("net_encr"):
                    print("[!] NET_ENCR_MODIFICATIONS")
                    
                if policy.get("sec_boot") != policy_tmp.get("sec_boot"):
                    print("[!] SEC_BOOT_MODIFICATIONS")
                    
                break

            if not found:
                print("[!] Service not found")   
                print("[!] Deleting service policies...")
                delPolicies(policy.get("ip"))
    
    print("[!] New policies_list: ")
    print(policies_list)


#del policies when service not found
def delPolicies(ip):
    for te in sh.Table_entry("my_ingress.ipv4_exact").read():
        if te.match["hdr.ipv4.srcAddr"] == ip:
            te.delete()


#edit service ip 
def editIPPolicies(old_ip, new_ip, port):
    for te in sh.TableEntry("my_ingress.ipv4_exact").read():
        if te.match["hdr.ipv4.srcAddr"] == old_ip:
            src_addr = te.match["hdr.ipv4.src_addr"]
            te.delete()
            te = sh.TableEntry('my_ingress.ipv4_exact')(action='my_ingress.ipv4_forward')
            te.match["hdr.ipv4.srcAddr"] = src_addr
            te.match["hdr.ipv4.dstAddr"] = new_ip
            te.action["port"] = port
            te.insert()


#edit service port
def editPortPolicies(ip, new_port):
    for te in sh.TableEntry("my_ingress.ipv4_exact").read():
        if te.match["hdr.ipv4.srcAddr"] == ip:
            src_addr = te.match["hdr.ipv4.src_addr"]
            te.delete()
            te = sh.TableEntry('my_ingress.ipv4_exact')(action='my_ingress.ipv4_forward')
            te.match["hdr.ipv4.srcAddr"] = src_addr
            te.match["hdr.ipv4.dstAddr"] = ip
            te.action["port"] = new_port
            te.insert()


#delete a policy (old service, user not allowed anymore)
def delUE(ue_ip, service_ip):
    for te in table_entry["my_ingress.ipv4_exact"].read():
        if te.match["hdr.ipv4.srcAddr"] == ue_ip and te.match["hdr.ipv4.dstAddr"] == service_ip:
            te.delete()


#add a new entry
def addEntry(ip_src, ip_dst, port):
    te = sh.TableEntry('my_ingress.ipv4_exact')(action='my_ingress.ipv4_forward')
    te.match["hdr.ipv4.srcAddr"] = ip_src
    te.match["hdr.ipv4.dstAddr"] = ip_dst
    te.action["port"] = port
    te.insert()
    print("[!] New entry added")


#update policies_list
def getPolicies():
    #policyDB as a yaml file
    #each policy is a tuple containing specific attributes
    global policies_list 
    stream = open("policiesDB.yaml", 'r')
    policies_list = yaml.safe_load(stream)
    
    #if policyDB is a .txt file
    #policies = []
    #with open("policiesDB.txt", 'r') as f:
    #    print("policiesDB.txt opened")
    #    line = f.readline()
    #    while line:
    #        policies.append(line.split(" "))
    #        line = f.readline()


#if policyDB is managed as a true db
def getPoliciesDB(packet):
    global policies_list
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
                policies_list = cursor.fetchall()
            print(policies)

    except Error as e:
        print(e)


#look for policy and add new entries if found (when a packet is received)
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
            addEntry(src, dst, dport)
            
            #add bi-directional entry if icmp packet
            if pkt_icmp != None and pkt_ip != None and str(pkt_icmp.getlayer(ICMP).type) == "8":
                addEntry(dst, src, sport)
            found = True
            break
    
    if not found:
        #packet drop
        packet = None
        print("[!] Packet dropped\n\n\n")


#handle a just received packet
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
            lookForPolicy(policies_list, pkt)
        elif pkt_ip != None:
            print("[!] Packet received: " + pkt_src + "-->" + pkt_dst)
            lookForPolicy(policies_list, pkt)
        else:
            print("[!] No needed layer (ARP, DNS, ...)")


#setup connection \w switch, sets policies_list, starts mod_detector thread and listens for new packets
def controller():
    global policies_list

    #connection
    sh.setup(
        device_id=0,
        grpc_addr='192.187.3.8:50051', #substitute ip and port with the ones of the specific switch
        election_id=(1, 0), # (high, low)
        config=sh.FwdPipeConfig('p4-test.p4info.txt','p4-test.json')
    )

    #get and save policies_list    
    getPolicies()

    #thread that checks for policies modifications
    detector = threading.Thread(target = mod_detecter)
    detector.start()

    #listening for new packets
    while True:
        packets = None
        print("Waiting for receive something")
        packet_in = sh.PacketIn()
        packets = packet_in.sniff(timeout=5)
        for streamMessageResponse in packets:
            packetHandler(streamMessageResponse)

if __name__ == '__main__':
    controller()