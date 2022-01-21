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
mac_addresses = {}

#open_entry_history = [{"ip_dst":"10.0.0.3", "ip_src":"10.0.0.1", "port":80, "ether_src":"ff:ff:ff:ff:ff:ff", "te":table_entry}, {...}, ...]
open_entry_history = []

#strict_entry_history = [{"ip_dst":"10.0.0.3", "ip_src":"10.0.0.1", "dport":80, "sport":1298, "dstAddr":"ff:ff:ff:ff:ff:ff", egress_port":2 "te":table_entry}, {...}, ...]
strict_entry_history = []

#add - to each value but last one
def auth_param(param):
    return param + "-"

#layer Auth definition
class Auth(Packet):
    fields_desc = []
    fields_desc.append(StrLenField("service_ip", auth_param("10.0.2.15"))) #10.0.0.1 as default
    fields_desc.append(StrLenField("method", auth_param("imsi"))) #imsi as default
    fields_desc.append(StrLenField("authentication", auth_param("310170845466094"))) #310170845466094 as default
    fields_desc.append(StrLenField("port", auth_param("80"))) #80 as default
    fields_desc.append(StrLenField("protocol", "TCP")) #TCP as default

#check if PolicyDB has been modified
def mod_detector():
    while True:
        i = inotify.adapters.Inotify()
        i.add_watch("../orchestrator/policiesDB.yaml")

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
    global mac_addresses
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
                        stream = open("../orchestrator/ip_map.yaml", 'r')
                        mapping = yaml.safe_load(stream)
                        for service in mapping: #leverage on ip_map to get sport for bidirectional traffic
                            if service.get("serviceName") == policy.get("serviceName") and service.get("ip") == policy.get("ip"): #same service and ip
                                for user in service.get("allowed_users"):
                                    if ue.get("method") == "ip" and user.get("actual_ip") == ue.get("user"): #ip already available; maybe not needed, but for the sake of completeness
                                        addEntry(ue.get("actual_ip"), policy.get("ip"), policy.get("port"), user.get("sport"), mac_addresses[policy.get("ip")], 2)
                                        #add bi-directional entry 
                                        addEntry(policy.get("ip"), ue.get("actual_ip"), user.get("sport"), policy.get("port"), mac_addresses[user.get("actual_ip")], 1)
                                    else:
                                        if (user.get("method") == "imsi" and user.get("imsi") == ue.get("user")) or (user.get("method") == "token" and user.get("token") == ue.get("user")): #same method and same id (imsi or token)
                                            addEntry(user.get("actual_ip"), policy.get("ip"), policy.get("port"), user.get("sport"), mac_addresses[policy.get("ip")], 2)
                                            #add bi-directional entry 
                                            addEntry(policy.get("ip"), user.get("actual_ip"), user.get("sport"), policy.get("port"), mac_addresses[user.get("actual_ip")], 1)
                #del
                for ue in policy_tmp.get("allowed_users"):
                    if ue not in policy.get("allowed_users"):
                        print("[!] UE_MODIFICATIONS_DEL")
                        if ue.get("method") == "ip": #ip already available, no need to check mapping to find ip to be deleted
                            delUE(ue.get("user") , policy.get("ip"))
                            #del bi-directional entry
                            delUE(policy.get("ip"), ue.get("user"))
                        else: #imsi or token
                            stream = open("../orchestrator/ip_map.yaml", 'r')
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
    global strict_entry_history
    for dictionary in strict_entry_history:
        if dictionary["ip_dst"] == ip:
            dictionary["te"].delete()
            strict_entry_history.remove(dictionary)

#edit service ip (also bidirectional entry)
def editIPPolicies(old_ip, new_ip, port):
    global strict_entry_history
    for dictionary in strict_entry_history:
        if dictionary["ip_dst"] == old_ip:
            dictionary["te"].delete()        
            addEntry(dictionary["ip_src"], new_ip, dictionary["dport"], dictionary["sport"], dictionary["dstAddr"], dictionary["egress_port"])
            dictionary["ip_dst"] == new_ip

    for dictionary in strict_entry_history:
        if dictionary["ip_src"] == old_ip:
            dictionary["te"].delete()        
            addEntry(new_ip, dictionary["ip_dst"], dictionary["dport"], dictionary["sport"], dictionary["dstAddr"], dictionary["egress_port"])
            dictionary["ip_src"] == new_ip

#edit service port (bidirectional entry not needed -> sport is not necessary)
def editPortPolicies(ip, new_port):
    global strict_entry_history
    for dictionary in strict_entry_history:
        if dictionary["ip_dst"] == ip:
            dictionary["te"].delete()        
            addEntry(dictionary["ip_src"], ip, new_port, dictionary["sport"], dictionary["dstAddr"], dictionary["egress_port"])
            dictionary["dport"] == new_port

    for dictionary in strict_entry_history:
        if dictionary["ip_src"] == ip:
            dictionary["te"].delete()        
            addEntry(ip, dictionary["ip_dst"], dictionary["dport"], new_port, dictionary["dstAddr"], dictionary["egress_port"])
            dictionary["sport"] == new_port

#delete a policy (old service, user not allowed anymore)
def delUE(ue_ip, service_ip):
    global strict_entry_history
    for dictionary in strict_entry_history:
        if dictionary["ip_src"] == ue_ip and dictionary["ip_dst"] == service_ip:
            dictionary["te"].delete()
            strict_entry_history.remove(dictionary)

    for dictionary in strict_entry_history:
        if dictionary["ip_src"] == service_ip and dictionary["ip_dst"] == ue_ip:
            dictionary["te"].delete()
            strict_entry_history.remove(dictionary)

#add a new tmp "open" entry
def addOpenEntry(ip_src, ip_dst, port, ether_dst, egress_port, ether_src):
    global open_entry_history
    te = sh.TableEntry('my_ingress.forward')(action='my_ingress.ipv4_forward')
    te.match["hdr.ipv4.srcAddr"] = ip_src
    te.match["hdr.ipv4.dstAddr"] = ip_dst
    te.match["dst_port"] = str(port)
    te.action["dstAddr"] = ether_dst
    te.action["port"] = str(egress_port)
    te.priority = 1
    te.insert()
    print("[!] New open entry added")
    open_entry_history.append({"ip_dst":ip_dst, "ip_src":ip_src, "port":str(port), "ether_src":ether_src, "te":te})

    def entry_timeout(ip_dst, ip_src, port, ether_src):
        global open_entry_history
        timeout = time.time() + 10.0 #2 sec or more
        while True:
            entry = {}
            found = False
            for dictionary in open_entry_history:
                if dictionary["ip_dst"] == ip_dst and dictionary["ip_src"] == ip_src and dictionary["port"] == port and dictionary["ether_src"] == ether_src:
                    entry = dictionary
                    found = True

            #open entry has been deleted
            if not found:
                break

            if timeout - time.time() <= 0.0:
                #delete open entry
                entry["te"].delete()
                open_entry_history.remove(entry)
                print("[!] Open entry deleted, timeout")
                break

    open_entry_timeout = threading.Thread(target = entry_timeout, args = (ip_dst, ip_src, port, ether_src,)).start()

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
    strict_entry_history.append({"ip_dst":ip_dst, "ip_src":ip_src, "dport":str(dport), "sport":str(sport), "dstAddr":ether_dst, "egress_port":egress_port, "te":te})

#update policies_list
def getPolicies():
    #policyDB as a yaml file
    #each policy is a tuple containing specific attributes
    global policies_list
    stream = open("../orchestrator/policiesDB.yaml", 'r')
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
    global mac_addresses
    found = False
    print("[!] Policies: \n")
    print(policyList)

    pkt_ip = pkt.getlayer(IP)
    src = pkt_ip.src
    dst = pkt_ip.dst

    pkt_ether = pkt.getlayer(Ether)
    ether_src = mac_addresses[src]
    ether_dst = mac_addresses[dst]

    pkt_udp = pkt.getlayer(UDP)
    sport = pkt_udp.sport
    dport = pkt_udp.dport

    #raw parsing
    pkt_auth = str(pkt.getlayer(Raw)).split("-")
    service_ip = pkt_auth[0][2:] #remove 'b
    method = pkt_auth[1]
    authentication = pkt_auth[2]
    port = pkt_auth[3]
    protocol = pkt_auth[4][:-1] #remove '

    print("\nsrc_ether: " + ether_src)
    print("dst_ether: " + ether_dst)
    print("src_ip: " + src)
    print("dst_ip: " + dst)
    print("sport: " + str(sport))
    print("dport: " + str(dport))
    print("service_ip: " + service_ip)
    print("method: " + method)
    print("authentication: " + authentication)
    print("port: " + port)
    print("protocol: " + protocol)

    for policy in policyList:
        if service_ip == policy.get("ip") and int(port) == policy.get("port") and protocol == policy.get("protocol"):
            for user in policy.get("allowed_users"):
                if method == "ip":
                    if user.get("method") == "ip" and user.get("user") == authentication:
                        found = True
                        addOpenEntry(authentication, service_ip, port, ether_dst, 2, ether_src) #substitute specific egress_port; 2 in my case
                        break
                else: #imsi or token
                    stream = open("../orchestrator/ip_map.yaml", 'r')
                    mapping = yaml.safe_load(stream)
                    for service in mapping:
                        if service.get("serviceName") == policy.get("serviceName") and service.get("ip") == policy.get("ip"): #same service and ip
                            for user in service.get("allowed_users"):
                                if user.get("method") == ue.get("method") and ue.get("method") == method and user.get("user") == ue.get("user") and ue.get("user") == authentication: #same method and same id (imsi or token)
                                    found = True
                                    addOpenEntry(user.get("actual_ip"), policy.get("ip"), policy.get("port"), ether_dst, 2, ether_src)
                                    break
    if not found:
        #packet drop
        packet = None
        print("[!] Packet dropped\n\n\n")

#add new ip-mac entry to dictionary
def arpManagement(packet):
    global mac_addresses
    mac = packet.getlayer(Ether).src
    ip = packet.getlayer(ARP).psrc
    print(ip + " has MAC " + mac)
    if ip not in mac_addresses:
        mac_addresses[ip] = mac
    print(mac_addresses)

#handle a just received packet
def packetHandler(streamMessageResponse):
    global mac_addresses
    print("[!] Packets received")
    packet = streamMessageResponse.packet

    if streamMessageResponse.WhichOneof('update') =='packet':
        packet_payload = packet.payload
        pkt = Ether(_pkt=packet.payload)
        ether_src = pkt.getlayer(Ether).src
        ether_dst = pkt.getlayer(Ether).dst

        if pkt.getlayer(IP) != None:
            pkt_src = pkt.getlayer(IP).src
            pkt_dst = pkt.getlayer(IP).dst

        if pkt.getlayer(TCP) != None:
            sport = pkt.getlayer(TCP).sport
            dport = pkt.getlayer(TCP).dport

        pkt_icmp = pkt.getlayer(ICMP)
        pkt_ip = pkt.getlayer(IP)
        pkt_arp = pkt.getlayer(ARP)
        pkt_udp = pkt.getlayer(UDP)
        pkt_auth = pkt.getlayer(Auth)

        reply = False
        #check for waited replies in open_entry_history
        for dictionary in open_entry_history:
            if pkt_src == dictionary["ip_dst"] and pkt_dst == dictionary["ip_src"]:
                if pkt.getlayer(TCP) != None:
                    if str(pkt.getlayer(TCP).sport) == dictionary["port"]:
                        reply = True
                        print("[!] Reply arrived")
                        #delete open entry
                        dictionary["te"].delete()
                        print("[!] Open entry deleted")
                        open_entry_history.remove(dictionary)
                        #add strict entries
                        print(pkt.getlayer(Ether).src)
                        print(dictionary["ether_src"])
                        addEntry(pkt_src, pkt_dst, pkt.getlayer(TCP).dport, dictionary["port"], dictionary["ether_src"], 1)
                        addEntry(pkt_dst, pkt_src, dictionary["port"], pkt.getlayer(TCP).dport, ether_src, 2)

        if not reply:
            if pkt_icmp != None and pkt_ip != None and str(pkt_icmp.getlayer(ICMP).type) == "8":
                print("[!] Ping from: " + pkt_src)
                print("[!] ICMP layer not supported in p4 switch, not used")
            elif pkt_arp != None:
                print("[!] ARP info")
                arpManagement(pkt)
            elif pkt_ip != None:
                print("[!] Packet received: " + pkt_src + " --> " + pkt_dst)
                if pkt.getlayer(TCP) != None:
                    print("sport: " + str(pkt.getlayer(TCP).sport))
                    print("dport: " + str(pkt.getlayer(TCP).dport))
                if pkt_udp != None and pkt_auth != None: #dst mac already known and UDP packet w\ auth layer
                    if pkt_src in mac_addresses and pkt_dst in mac_addresses:
                        lookForPolicy(policies_list, pkt)
                    else:
                        print("[!] MAC info not known, still waiting for a gratuitous ARP packet. Here are all the collected info")
                        print(mac_addresses)
            else:
                print("[!] No needed layers")

#setup connection \w switch, sets policies_list, starts mod_detector thread and listens for new packets
def controller():
    global policies_list

    #connection
    sh.setup(
        device_id=1,
        grpc_addr='172.17.0.1:55389', #substitute ip and port with the ones of the specific switch
        election_id=(1, 0), # (high, low)
        config=sh.FwdPipeConfig('../p4/p4-test.p4info.txt','../p4/p4-test.json')
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
    bind_layers(UDP, Auth, sport=1298, dport = 1299)
    bind_layers(Auth, Raw)
    packet_in = sh.PacketIn()
    threads = []
    while True:
        print("[!] Waiting for receive something")

        def handle_thread_pkt_management(packet, threads):
            packet_handler = threading.Thread(target = packetHandler, args = (packet,))
            threads.append(packet_handler)
            packet_handler.start()
            print("[!] packet_handler started")
            for thread in threads:
                thread.join()

        packet_in.sniff(lambda m: handle_thread_pkt_management(m, threads), timeout = 1)

if __name__ == '__main__':
    controller()