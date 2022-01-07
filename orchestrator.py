import grpc
import os
import sys
import p4runtime_sh.shell as sh
from p4runtime_sh.shell import PacketIn
import time
from scapy.all import *
import yaml
import threading
import inotify.adapters

# No need to import p4runtime_lib
# import p4runtime_lib.bmv2

policies_list = []

#check if PolicyDB has been modified
def mod_detector():
    while True:
        i = inotify.adapters.Inotify()
        i.add_watch("../CES/policiesDB.yaml")

        for event in i.event_gen(yield_nones=False):
            (_, type_names, path, filename) = event

            if "IN_CLOSE_WRITE" in event[1]: #type_names is a list
                print("[!] POLICYDB MODIFIED")
                mod_manager()

            #log:
            #print("PATH=[{}] FILENAME=[{}] EVENT_TYPES={}".format(path, filename, type_names))

#find out specific modifications per policy
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
                    editIPPolicies(policy_tmp.get("ip"), policy.get("ip"), policy.get("port")) #also bidirectional entry

                if policy.get("port") != policy_tmp.get("port"):
                    print("[!] PORT_MODIFICATIONS")
                    print("[!] Editing policies Port...")
                    editPortPolicies(policy_tmp.get("ip"), policy_tmp.get("port")) #bidirectional entry not needed

                if policy.get("protocol") != policy_tmp.get("protocol"):
                    print("[!] PROTOCOL_MODIFICATIONS")
                    
                #UE checks
                #add
                for ue in policy.get("allowed_users"):
                    if ue not in policy_tmp.get("allowed_users"):
                        print("[!] UE_MODIFICATIONS_ADD")
                        stream = open("../CES/ip_map.yaml", 'r')
                        mapping = yaml.safe_load(stream)
                        for service in mapping: #leverage on ip_map to get sport for bidirectional traffic
                            if service.get("serviceName") == policy.get("serviceName") and service.get("ip") == policy.get("ip"): #same service and ip
                                for user in service.get("allowed_users"):
                                    if ue.get("method") == "ip" and user.get("actual_ip") == ue.get("user"): #ip already available; maybe not needed, but for the sake of completeness
                                        addEntry(ue.get("actual_ip"), policy.get("ip"), policy.get("port"), user.get("sport"), policy.get("serviceEther"), 2)
                                        #add bi-directional entry 
                                        addEntry(policy.get("ip"), ue.get("actual_ip"), user.get("sport"), policy.get("port"), user.get("ether"), 1)
                                    else:
                                        if (user.get("method") == "imsi" and user.get("imsi") == ue.get("user")) or (user.get("method") == "token" and user.get("token") == ue.get("user")): #same method and same id (imsi or token)
                                            addEntry(user.get("actual_ip"), policy.get("ip"), policy.get("port"), user.get("sport"), policy.get("serviceEther"), 2)
                                            #add bi-directional entry 
                                            addEntry(policy.get("ip"), user.get("actual_ip"), user.get("sport"), policy.get("port"), user.get("ether"), 1)
                #del
                for ue in policy_tmp.get("allowed_users"):
                    if ue not in policy.get("allowed_users"):
                        print("[!] UE_MODIFICATIONS_DEL")
                        if ue.get("method") == "ip": #ip already available, no need to check mapping to find ip to be deleted
                            delUE(ue.get("user") , policy.get("ip"))
                            #del bi-directional entry
                            delUE(policy.get("ip"), ue.get("user"))
                        else: #imsi or token
                            stream = open("../CES/ip_map.yaml", 'r')
                            mapping = yaml.safe_load(stream)
                            for service in mapping:
                                if service.get("serviceName") == policy.get("serviceName") and service.get("ip") == policy.get("ip"): #same service and ip
                                    for user in service.get("allowed_users"):
                                        if (user.get("method") == "imsi" and user.get("imsi") == ue.get("user")) or (user.get("method") == "token" and user.get("token") == ue.get("user")): #same method and same id (imsi or token)
                                            delUE(user.get("actual_ip"), policy.get("ip"))
                                            #del bi-directional entry
                                            delUE(policy.get("ip"), user.get("actual_ip"))

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
                delPolicies(policy.get("ip"), policy.get("protocol"))
    
    print("[!] New policies_list: ")
    print(policies_list)

#del policies when service not found
def delPolicies(ip):
    for te in sh.Table_entry("my_ingress.forward").read():
        if te.match["hdr.ipv4.dstAddr"] == ip:
            te.delete()

#edit service ip (also bidirectional entry)
def editIPPolicies(old_ip, new_ip, port):
    for te in sh.TableEntry("my_ingress.forward").read():
        if te.match["hdr.ipv4.dstAddr"] == old_ip:
            src_addr = te.match["hdr.ipv4.srcAddr"]
            src_port = te.match["src_port"]
            egress_port = te.action["port"]
            dstAddr = te.action["dstAddr"]
            te.delete()
            addEntry(src_addr, new_ip, port, src_port, dstAddr, egress_port)

    for te in sh.TableEntry("my_ingress.forward").read():
        if te.match["hdr.ipv4.srcAddr"] == old_ip:
            dst_addr = te.match["hdr.ipv4.dstAddr"]
            egress_port = te.action["port"]
            dstAddr = te.action["dstAddr"]
            dst_port = te.action["dst_port"]
            te.delete()
            addEntry(new_ip, dst_addr, dst_port, port, dstAddr, egress_port)

#edit service port (bidirectional entry not needed -> sport is not necessary)
def editPortPolicies(ip, new_port):
    for te in sh.TableEntry("my_ingress.forward").read():
        if te.match["hdr.ipv4.srcAddr"] == ip:
            src_addr = te.match["hdr.ipv4.src_addr"]
            dstAddr = te.action["dstAddr"]
            src_port = te.action["src_port"]
            egress_port = te.action["port"]
            te.delete()
            addEntry(src_addr, ip, new_port, src_port, dstAddr, egress_port)

#delete a policy (old service, user not allowed anymore)
def delUE(ue_ip, service_ip):
    for te in sh.Table_entry("my_ingress.forward").read():
        if te.match["hdr.ipv4.srcAddr"] == ue_ip and te.match["hdr.ipv4.dstAddr"] == service_ip:
            te.delete()

#add a new tmp "open" entry
def addOpenEntry(ip_src, ip_dst, port, ether_dst, egress_port):
    te = sh.TableEntry('my_ingress.forward')(action='my_ingress.ipv4_forward')
    te.match["hdr.ipv4.srcAddr"] = ip_src
    te.match["hdr.ipv4.dstAddr"] = ip_dst
    te.match["dst_port"] = str(port)
    te.action["dstAddr"] = ether_dst
    te.action["port"] = str(egress_port)
    te.priority = 1
    te.insert()
    print("[!] New open entry added")
    reply = threading.Thread(target = waitForReply(ip_dst, ip_src, port)).start() #another thread not to block orchestrator
    reply.start()
    reply.join()
    te.delete() #entry to be deleted anyway
    print("[!] Open entry deleted")

def waitForReply(ip_dst, ip_src, dport):
    timeout = time.time() + 2.0 #2 sec or more
    while True:
        packets = None
        print("Waiting for reply")
        packet_in = sh.PacketIn()

        def collecting_packets(packets):
            packets += packet_in.sniff(timeout=5)

        packet_collector = threading.Thread(target = collecting_packets, args = (packets, ))
        packet_collector.start()
        print("[!] packet_collector started")
        packet_collector.join()
        print("[!] packet_collector ended")
        for streamMessageResponse in packets:
            packet = streamMessageResponse.packet
            if streamMessageResponse.WhichOneof('update') =='packet':
                packet_payload = packet.payload
                pkt = Ether(_pkt=packet.payload)
                if pkt.getlayer(IP) != None:
                    pkt_src = pkt.getlayer(IP).src
                    pkt_dst = pkt.getlayer(IP).dst
                    if pkt_src == ip_dst and pkt_dst == ip_src:
                        if pkt.getlayer(TCP) != None:
                            if dport == pkt.getlayer(TCP).sport:
                                addEntry(ip_src, ip_dst, dport, pkt.getlayer(TCP).dport, pkt.getlayer(Ether).dstAddr, 2)
                                addEntry(ip_dst, ip_src, pkt.getlayer(TCP).dport, dport, pkt.getlayer(Ether).srcAddr, 1)
                        break
        if timeout - time.time() <= 0.0:
            break

#add a new "strict" (sport -> microsegmentation) entry
def addEntry(ip_src, ip_dst, dport, sport, ether_dst, egress_port):
    te = sh.TableEntry('my_ingress.forward')(action='my_ingress.ipv4_forward')
    te.match["hdr.ipv4.srcAddr"] = ip_src
    te.match["hdr.ipv4.dstAddr"] = ip_dst
    te.match["src_port"] = str(sport)
    te.match["dst_port"] = str(dport)
    te.action["dstAddr"] = ether_dst
    te.action["port"] = str(egress_port)
    te.priority = 1
    te.insert()
    print("[!] New entry added")

#update policies_list
def getPolicies():
    #policyDB as a yaml file
    #each policy is a tuple containing specific attributes
    global policies_list 
    stream = open("../CES/policiesDB.yaml", 'r')
    policies_list = yaml.safe_load(stream)

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
    
    pkt_ether = pkt.getlayer(Ether)
    ether_src = pkt_ether.srcAddr
    ether_dst = pkt_ether.dstAddr
    
    pkt_ip = pkt.getlayer(IP)
    if pkt_ip != None:
        src = pkt_ip.src
        dst = pkt_ip.dst
    else:
        print("\n[!] IP layer not present")
        return

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

    print("\nsrc_ether: " + ether_src)
    print("dst_ether: " + ether_dst)
    print("src_ip: " + src)
    print("dst_ip: " + dst)
    print("sport: " + str(sport))
    print("dport: " + str(dport))
    print("protocol: " + protocol)
    
    for policy in policyList:
        #policy_tuple.get("dst")
        if dst == policy.get("ip") and ether_dst == policy.get("serviceEther") and dport == policy.get("port") and protocol == policy.get("protocol"):
            for user in policy.get("allowed_users"):
                if user.get("method") == "ip" and user.get("user") == src:
                    found = True
                    addOpenEntry(src, dst, dport, policy.get("serviceEther"), 2) #substitute specific egress_port; 2 in my case
                    break
                else: #imsi or token
                    stream = open("../CES/ip_map.yaml", 'r')
                    mapping = yaml.safe_load(stream)
                    for service in mapping:
                        if service.get("serviceName") == policy.get("serviceName") and service.get("ip") == policy.get("ip"): #same service and ip
                            for user in service.get("allowed_users"):
                                if user.get("method") == ue.get("method") and user.get("user") == ue.get("user"): #same method and same id (imsi or token)
                                    found = True
                                    addOpenEntry(user.get("actual_ip"), policy.get("ip"), policy.get("port"), policy.get("serviceEther"), 2)
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
        #ether_type = pkt.getlayer(Ether).type
        pkt_icmp = pkt.getlayer(ICMP)
        pkt_ip = pkt.getlayer(IP)
        
        if pkt_icmp != None and pkt_ip != None and str(pkt_icmp.getlayer(ICMP).type) == "8":
            print("[!] Ping from: " + pkt_src)
            lookForPolicy(policies_list, pkt)
        elif pkt_ip != None:
            print("[!] Packet received: " + pkt_src + " --> " + pkt_dst)
            lookForPolicy(policies_list, pkt)
        else:
            print("[!] No needed layer (ARP, DNS, ...)")

#setup connection \w switch, sets policies_list, starts mod_detector thread and listens for new packets
def controller():
    global policies_list

    #connection
    sh.setup(
        device_id=1,
        grpc_addr='172.17.0.1:46985', #substitute ip and port with the ones of the specific switch
        election_id=(1, 0), # (high, low)
        config=sh.FwdPipeConfig('../CES/p4-test.p4info.txt','../CES/p4-test.json')
    )

    #deletion of already-present entries
    print("[!] Entries initial deletion")
    for te in sh.TableEntry("my_ingress.forward").read():
        te.delete()

    #get and save policies_list    
    getPolicies()

    #thread that checks for policies modifications
    print("[!] Policies modifications detector started")
    detector = threading.Thread(target = mod_detector)
    detector.start()

    #listening for new packets
    while True:
        packets = []
        print("[!] Waiting for receive something")
        packet_in = sh.PacketIn()
        
        def collecting_packets(packets):
            packets += packet_in.sniff(timeout=5)
        
        packet_collector = threading.Thread(target = collecting_packets, args = (packets, ))
        packet_collector.start()
        print("[!] packet_collector started")
        packet_collector.join()
        print("[!] packet_collector ended")
        threads = []
        for streamMessageResponse in packets:
            packet_handler = threading.Thread(target = packetHandler, args = (streamMessageResponse,))
            threads.append(packet_handler)
            packet_handler.start()
            print("[!] packet_handler started")
        for thread in threads:
            thread.join()
            
if __name__ == '__main__':
    controller()