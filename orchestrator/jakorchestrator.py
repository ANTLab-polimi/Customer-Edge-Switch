import grpc
import os
import random
import hashlib
import sys
import p4runtime_sh.shell as sh
from p4runtime_sh.shell import PacketIn
from p4runtime_sh.shell import PacketOut
import time
from scapy.all import *
import yaml
import threading
import inotify.adapters
import json, base64
import hmac
import socket
import json
from json import JSONEncoder
from scapy.contrib.nsh import *
from scapy.contrib.oncrpc import *

# this class stands for the hmac creation so we can create the hamc here in the control plan and then put it in the hmac_table
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

controller_ip = '192.168.56.2'
key_port = 100
# WE ARE SUPPOSING THAT THE PORT IS A FIXED ONE AND THAT WE KNOW IT
http_port = 80
mac_to_be_filtered = '0a:00:27:00:00:20' #virtualbox mac to be filtered

policies_list = []
mac_addresses = {}
#keys = [{"imsi":"5021301234567894", "key":"6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b", "count":1}, {...}, ...]
keys = []

#open_entry_history = [{"ip_dst":"10.0.0.3", "ip_src":"10.0.0.1", "port":80, "ether_src":"ff:ff:ff:ff:ff:ff", "te":table_entry}, {...}, ...]
open_entry_history = []

#strict_entry_history = [{"ip_dst":"10.0.0.3", "ip_src":"10.0.0.1", "dport":80, "sport":1298, "dstAddr":"ff:ff:ff:ff:ff:ff", egress_port":2 "te":table_entry}, {...}, ...]
strict_entry_history = []

#hash_entry_history = [{"ip_dst":"10.0.0.3", "ip_src":"10.0.0.1", "dport":80, "sport":1298, "srcAddr":"ff:ff:ff:ff:ff:ff", "dstAddr":"ff:ff:ff:ff:ff:ff", "egress_port":2, "hmac":hmac_hex, "te":table_entry}, {...}, ...]
hash_entry_history = []

# check if PolicyDB has been modified
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

# find out specific modifications per policy
def mod_manager():
    global policies_list
    global mac_addresses
    global strict_entry_history
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
                    editPortPolicies(policy_tmp.get("ip"), policy.get("port"))

                if policy.get("protocol") != policy_tmp.get("protocol"):
                    print("[!] PROTOCOL_MODIFICATIONS")

                #UE checks
                #add -> no need to add entries
                for ue in policy.get("allowed_users"):
                    if ue not in policy_tmp.get("allowed_users"):
                        print("[!] UE_MODIFICATIONS_ADD")
                #del -> need to delete previous entries
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
                                if service.get("serviceName") == policy.get("serviceName") and service.get("ip") == policy.get("ip") and str(service.get("port")) == str(policy.get("port")): #same service, ip and port
                                    for user in service.get("allowed_users"):
                                        if user.get("method") == ue.get("method") and user.get("user") == ue.get("user"):
                                            delUE(user.get("actual_ip"), policy.get("ip"))
                
                '''
                Now these parameters are set in another different file, so there is no need to check them

                if policy.get("tee") != policy_tmp.get("tee"):
                    print("[!] TEE_MODIFICATIONS")

                if policy.get("fs_encr") != policy_tmp.get("fs_encr"):
                    print("[!] FS_ENCR_MODIFICATIONS")

                if policy.get("net_encr") != policy_tmp.get("net_encr"):
                    print("[!] NET_ENCR_MODIFICATIONS")

                if policy.get("sec_boot") != policy_tmp.get("sec_boot"):
                    print("[!] SEC_BOOT_MODIFICATIONS")
                '''

                break

        if not found:
            print("[!] Service not found")
            print("[!] Deleting service policies...")
            delPolicies(policy_tmp.get("ip"))

    print("[!] New policies_list: ")
    print(policies_list)

# del policies when service not found
def delPolicies(ip):
    global strict_entry_history
    for dictionary in strict_entry_history:
        if dictionary["ip_dst"] == ip:
            dictionary["te"].delete()
            strict_entry_history.remove(dictionary)

# edit service ip (also bidirectional entry)
def editIPPolicies(old_ip, new_ip, port):
    global strict_entry_history
    for dictionary in strict_entry_history:
        if dictionary["ip_dst"] == old_ip:
            dictionary["te"].delete()
            print("[!] Previous entry deleted")
            addEntry(dictionary["ip_src"], new_ip, dictionary["dport"], dictionary["sport"], dictionary["dstAddr"], dictionary["egress_port"], dictionary["srcAddr"])
            strict_entry_history.remove(dictionary)

        if dictionary["ip_src"] == old_ip:
            dictionary["te"].delete()
            print("[!] Previous entry deleted")
            addEntry(new_ip, dictionary["ip_dst"], dictionary["dport"], dictionary["sport"], dictionary["dstAddr"], dictionary["egress_port"], dictionary["srcAddr"])
            strict_entry_history.remove(dictionary)

# edit service port
def editPortPolicies(ip, new_port):
    global strict_entry_history
    for dictionary in strict_entry_history:
        if dictionary["ip_dst"] == ip:
            print(dictionary)
            dictionary["te"].delete()
            print("[!] Previous entry deleted")
            addEntry(dictionary["ip_src"], ip, new_port, dictionary["sport"], dictionary["dstAddr"], dictionary["egress_port"], dictionary["srcAddr"])
            strict_entry_history.remove(dictionary)

        if dictionary["ip_src"] == ip:
            dictionary["te"].delete()
            print("[!] Previous entry deleted")
            addEntry(ip, dictionary["ip_dst"], dictionary["dport"], new_port, dictionary["dstAddr"], dictionary["egress_port"], dictionary["srcAddr"])
            strict_entry_history.remove(dictionary)

# delete a policy (old service, user not allowed anymore)
def delUE(ue_ip, service_ip):
    global strict_entry_history
    for dictionary in strict_entry_history:
        if dictionary["ip_src"] == ue_ip and dictionary["ip_dst"] == service_ip:
            dictionary["te"].delete()
            print("[!] Previous entry deleted")
            strict_entry_history.remove(dictionary)

        if dictionary["ip_src"] == service_ip and dictionary["ip_dst"] == ue_ip:
            dictionary["te"].delete()
            print("[!] Previous entry deleted")
            strict_entry_history.remove(dictionary)

# add a new tmp "open" entry
def addOpenEntry(ip_src, ip_dst, port, ether_dst, egress_port, ether_src, who):
    global open_entry_history
    te = sh.TableEntry('my_ingress.forward')(action='my_ingress.ipv4_forward')
    te.match["hdr.ipv4.srcAddr"] = ip_src
    te.match["hdr.ipv4.dstAddr"] = ip_dst
    if who == "client":
        te.match["dst_port"] = str(port)
    else:
        te.match["src_port"] = str(port)
    te.action["dstAddr"] = ether_dst
    te.action["srcAddr"] = ether_src
    te.action["port"] = str(egress_port)
    te.priority = 1
    te.insert()
    inserted = time.time()
    print("[!] NEW OPEN ENTRY ADDED AT:" + str(inserted))
    open_entry_history.append({"ip_dst":ip_dst, "ip_src":ip_src, "port":str(port), "ether_dst":ether_dst, "ether_src":ether_src, "te":te})
    print(str(open_entry_history))

    def entry_timeout(ip_dst, ip_src, port, ether_src):
        global open_entry_history
        print("[!] Countdown started")
        timeout = time.time() + 70.0 #25 sec or more
        while True:
            entry = {}
            found = False
            for dictionary in open_entry_history:
                if dictionary["ip_dst"] == ip_dst and dictionary["ip_src"] == ip_src and dictionary["port"] == str(port) and dictionary["ether_src"] == ether_src:
                    entry = dictionary
                    found = True

            if timeout - time.time() <= 0.0 and found:
                # delete open entry
                entry["te"].delete()
                open_entry_history.remove(entry)
                print("[!] OPEN ENTRY DELETED DUE TO TIMEOUT")
                break
        return

    open_entry_timeout = threading.Thread(target = entry_timeout, args = (ip_dst, ip_src, port, ether_src,)).start()

# add a new "strict" (sport -> microsegmentation) entry
def addEntry(ip_src, ip_dst, dport, sport, ether_dst, egress_port, ether_src):
    te = sh.TableEntry('my_ingress.forward')(action='my_ingress.ipv4_forward')
    te.match["hdr.ipv4.srcAddr"] = ip_src
    te.match["hdr.ipv4.dstAddr"] = ip_dst
    te.match["src_port"] = str(sport)
    te.match["dst_port"] = str(dport)
    te.action["dstAddr"] = ether_dst
    te.action["srcAddr"] = ether_src
    te.action["port"] = str(egress_port)
    te.priority = 1
    te.insert()
    print("[!] New entry added")
    strict_entry_history.append({"ip_dst":ip_dst, "ip_src":ip_src, "dport":str(dport), "sport":str(sport), "srcAddr":ether_src, "dstAddr":ether_dst, "egress_port":egress_port, "te":te})
    print(str(strict_entry_history))

# update policies_list
def getPolicies():
    # policyDB as a yaml file
    # each policy is a tuple containing specific attributes
    global policies_list
    stream = open("../orchestrator/policiesDB.yaml", 'r')
    policies_list = yaml.safe_load(stream)

# if policyDB is managed as a true db
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

'''
    for policy in policyList:
        if service_ip == policy.get("ip") and int(port) == policy.get("port") and protocol == policy.get("protocol"):
            for user in policy.get("allowed_users"):
                if method == "ip":
                    if user.get("method") == "ip" and user.get("user") == client_ip[0]:
                    #if user.get("method") == "ip" and user.get("user") == authentication:
                        print("[IP METHOD] ADDED OPEN ENTRY AT " + str(time.time()))
                        found = True
                        addOpenEntry(authentication, service_ip, port, ether_dst, 2, ether_src) #substitute specific egress_port; 2 in my case
                        break
                else: #imsi or token
                    stream = open("../orchestrator/ip_map.yaml", 'r')
                    mapping = yaml.safe_load(stream)
                    for service in mapping:
                        if service.get("serviceName") == policy.get("serviceName") and service.get("ip") == policy.get("ip") and str(service.get("port")) == str(policy.get("port")): #same service, ip and port
                            for ue in service.get("allowed_users"):
                                if user.get("method") == ue.get("method") and ue.get("method") == method and user.get("user") == ue.get("user") and ue.get("user") == authentication: #same method and same id (imsi or token)
                                    found = True
                                    print("[!] Retrieved ip: " + ue.get("actual_ip"))
                                    addOpenEntry(ue.get("actual_ip"), policy.get("ip"), policy.get("port"), ether_dst, 2, ether_src)
                                    print("ADDED OPEN ENTRY AT " + str(time.time()))
                                    break
        else:
            print("[IP METHOD] POLICY METHOD PORT AND PROTOCOL NOOOOOOOOOOOOOOOOOOT MATCH")
'''
# look for policy for the given service_name and imsi
# if it exists, returns ip and port
# else returns -1
def lookForPolicy(policyList, service_name, imsi):
    global mac_addresses
    found = False

    service_port = 0
    service_ip = ''

    for policy in policyList:
        if service_name == policy.get("serviceName"):
            for user in policy.get("allowed_users"):
                if 'imsi' == user.get("method") and user.get("user") == imsi:
                    print("[POLICY CHECK] OK!")
                    found = True
                    service_port = policy.get("port")
                    service_ip = policy.get("ip")

    if not found:
        # packet drop
        packet = None
        service_ip = -1
        service_port = -2
        print("[!] Packet dropped\n\n\n")

    return (service_ip, service_port)

# add new ip-mac entry to dictionary
def arpManagement(packet):
    global mac_addresses
    mac = packet.getlayer(Ether).src
    if mac != mac_to_be_filtered:
        ip = packet.getlayer(ARP).psrc
        print(ip + " has MAC " + mac)
        if ip not in mac_addresses:
            mac_addresses[ip] = mac
        print(mac_addresses)

# diffie-hellman key computation
def key_computation(p, g, A, imsi, client_address, service_ip, service_port):
    global keys
    global mac_addresses
    found = False
    begin = time.time()
    print("BEGIN KEY COMPUTATION " + str(begin))
    for dictionary in keys:
        if dictionary["imsi"] == imsi:
            found = True

    if not found:
        b = random.randint(10,20)
        B = (int(g)**int(b)) % int(p)
        print("B: " + str(B))
        master_key = hashlib.sha256(str((int(A)**int(b)) % int(p)).encode()).hexdigest()
        print("master_key: " + str(master_key))
        keys.append({"imsi":imsi, "key":master_key, "count":1})

        ether_src = mac_addresses[client_address[0]]
        ether_dst = mac_addresses[service_ip]
        
        auth = Auth(service_ip, 'ip', client_address[0], service_port, 'TCP', imsi, 1, 1.0)
        auth = MyEncoder().encode(auth)
        message_bytes = auth.encode('ascii')
        base64_bytes = base64.b64encode(message_bytes)

        hash_hex = hashlib.shake_128(str(1).encode() + bytes(master_key, 'utf-8') + base64_bytes).hexdigest(16)
        #hash_hex = hmac.new(bytes(keyB, 'utf-8'), base64_bytes, hashlib.sha512).hexdigest()
        hash_time = time.time()
        print('HASH CALCULATED: ' + str(hash_hex) + "at" + str(hash_time))

        # inserting the entries in hmac table
        te = sh.TableEntry('my_ingress.hmac')(action='my_ingress.hmac_forward')
        te.match["hdr.nsh.metadata_payload"] = str(int(hash_hex,16))
        te.action["dstAddr"] = ether_dst
        te.action["srcAddr"] = ether_src
        te.priority = 0
        te.insert()
        hash_inserted = time.time()
        print("[!] New HASH entry added at:" + str(hash_inserted))
        hash_entry_history.append({"ip_dst":service_ip, "ip_src":client_address[0], "dport":service_port, "sport":client_address[1], "ether_src":ether_src, "ether_dst":ether_dst, "egress_port":2, "hash":hash_hex, "te":te})
        print(hash_entry_history)
        print("SERVICE TIME = " + str(hash_inserted-hash_time))        
        # inserting the entries in forward table
        addOpenEntry(client_address[0], service_ip, service_port, ether_dst, 2, ether_src, "client")
        addOpenEntry(service_ip, client_address[0], service_port, ether_src, 1, ether_dst, "service")

        return B
    else:
        print("[!] This imsi has already a master key")
        return -2

# handle a just received packets
def packetHandler(streamMessageResponse):
    global mac_addresses
    global keys
    packet = streamMessageResponse.packet

    if streamMessageResponse.WhichOneof('update') =='packet':
        packet_payload = packet.payload
        pkt = Ether(_pkt=packet.payload)

        #pkt.show()

        pkt_ether = pkt.getlayer(Ether)
        pkt_icmp = pkt.getlayer(ICMP)
        pkt_ip = pkt.getlayer(IP)
        pkt_arp = pkt.getlayer(ARP)
        pkt_tcp = pkt.getlayer(TCP)
        pkt_udp = pkt.getlayer(UDP)

        if pkt_ether != None:
            ether_src = pkt_ether.src
            ether_dst = pkt_ether.dst
        #else:
            #print("[!] Ether layer not present")

        if pkt_ip != None:
            pkt_src = pkt_ip.src
            pkt_dst = pkt_ip.dst
        #else:
            #print("[!] IP layer not present")

        if pkt_tcp != None:
            sport = pkt_tcp.sport
            dport = pkt_tcp.dport
        #else:
            #print("[!] TCP layer not present")

        if pkt_udp != None:
            sport = pkt_udp.sport
            dport = pkt_udp.dport
        #else:
            #print("[!] UDP layer not present")

        reply = False

        # my_filter = "ether proto arp or (ip host 192.168.56.6 and port host 80 and not rpc)"
        if pkt_arp != None or ( (pkt_tcp != None or pkt_udp != None) and (sport == http_port or dport == http_port) and (pkt_src == "192.168.56.6"  or pkt_dst == "192.168.56.6")):
        
            # check for waited replies in open_entry_history
            for dictionary in open_entry_history:
                #print("[PACKET HANDLER] CHECKING FOR OPEN ENTRY HISTORY...")
                #print(str(pkt.getlayer(IP)))
                #print(str(pkt_src), str(dictionary["ip_src"]), str(pkt_src == dictionary["ip_src"]))
                #print(str(pkt_dst), str(dictionary["ip_dst"]), str(pkt_dst == dictionary["ip_dst"]))
                if pkt_ip != None and pkt_src == dictionary["ip_src"] and pkt_dst == dictionary["ip_dst"]:
                    if pkt_tcp != None or pkt_udp != None:
                        if str(dport) == dictionary["port"]:
                            reply = True
                            #print("[!] Packet with NSH was arrived in data plane")
                            # we are supposing that this packet is the one with NSH (removed) and
                            # we need to insert the two rules strictly
                            # add strict entries
                            #addEntry(pkt_src, pkt_dst, dictionary["port"], pkt.getlayer(TCP).sport, dictionary["ether_dst"], 2, dictionary["ether_src"])
                            #addEntry(pkt_dst, pkt_src, pkt.getlayer(TCP).sport, dictionary["port"], dictionary["ether_src"], 1, dictionary["ether_dst"])
                            addEntry(pkt_src, pkt_dst, dictionary["port"], sport, dictionary["ether_dst"], 2, dictionary["ether_src"])
                            addEntry(pkt_dst, pkt_src, sport, dictionary["port"], dictionary["ether_src"], 1, dictionary["ether_dst"])
                            print("ADDED STRICT ENTRIES AT " + str(time.time()))
                            # delete open entries
                            dictionary["te"].delete()
                            print("[!] Open entry deleted")
                            open_entry_history.remove(dictionary)

                            # searching for the reverse open entry
                            for open_entry in open_entry_history:
                                if pkt_src == open_entry["ip_dst"] and pkt_dst == open_entry["ip_src"] and str(dport) == open_entry["port"]:
                                    open_entry["te"].delete()
                                    print("[!] Open entry deleted")
                                    open_entry_history.remove(open_entry)

            if not reply:
                #if pkt_icmp != None and pkt_ip != None and str(pkt_icmp.getlayer(ICMP).type) == "8":
                if pkt_icmp != None and pkt_ip != None and str(pkt_icmp.type) == "8":
                    print("[!] Ping from: " + pkt_src)
                    print("[!] ICMP layer not supported in p4 switch, not used")
                elif pkt_arp != None:
                    print("[!] ARP info")
                    arpManagement(pkt)
                elif pkt_ip != None:
                    print("[!] Packet received: " + pkt_src + " --> " + pkt_dst)
                    if pkt_tcp != None:
                        print("TCP layer:")
                        print("sport: " + str(sport))
                        print("dport: " + str(dport))
                    elif pkt_udp != None:
                        print("UDP layer:")
                        print("sport: " + str(sport))
                        print("dport: " + str(dport))
                else:
                    print("[!] No needed layers")

        else:
            print("[!] Packet discarded")

# setup connection w/ switch, sets policies_list, starts mod_detector thread and listens for new packets
# here there is condensed the main and all the CONTROL PLANE of the switch
def controller():
    global policies_list

    # connection
    sh.setup(
        device_id=1,
        grpc_addr='127.0.0.1:50051', #substitute ip and port with the ones of the specific switch
        election_id=(1, 0), # (high, low)
        config=sh.FwdPipeConfig('../p4/test.p4info.txt','../p4/test.json')
    )

    # deletion of already-present entries
    print("[!] Entries initial deletion")
    for te in sh.TableEntry("my_ingress.forward").read():
        te.delete()

    for te in sh.TableEntry("my_ingress.hmac").read():
        te.delete()

    # get and save policies_list
    getPolicies()

    # thread that checks for policies modifications
    print("[!] Policies modifications detector started")
    detector = threading.Thread(target = mod_detector)
    detector.start()

    # this is the thread that handles the diffie-hellman key exchange
    def dh_thread():
        global key_port
        global policies_list
        host = "0.0.0.0"
        server_cert = "../TLScertificate/server.crt"
        server_key = "../TLScertificate/server.key"
        client_certs = "../TLScertificate/client.crt"

        # for the TLS implementation: setting the SSLcontext for a mutual TLS connection
        # The most recent version of mutual TLS: https://www.electricmonk.nl/log/2018/06/02/ssl-tls-client-certificate-verification-with-python-v3-4-sslcontext/
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(    
            certfile=server_cert,
            keyfile=server_key
            )
        context.load_verify_locations(cafile=client_certs)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host, key_port))
        s.listen()

        while True:
            new_client, client_address = s.accept()

            # for the TLS implementation: wrapping the socket previously instantiated
            connection = context.wrap_socket(new_client, server_side=True)
            print("SSL established. Peer: {}".format(connection.getpeercert()))

            with connection:
                data = connection.recv(1024)
                print(str(data))
                data = str(data)[2:-1] #remove b' and '
                dh = json.loads(data)
                p = dh["p"]
                g = dh['g']
                A = dh['A']
                imsi = dh['imsi']
                service_name = dh['service_name']

                # checking the policy if this imsi is authenticated for this service_name
                service_ip_port = lookForPolicy(policies_list, service_name, imsi)

                B = 0
                if service_ip_port[0] == -1:
                    print("[DH_THREAD] There is no policy with that name or that imsi is not authenticated")
                    B = -1
                else:
                    if dh['version'] == 1.0: # version
                        B = key_computation(p, g, A, imsi, client_address, service_ip_port[0], service_ip_port[1])

                # B = 0, something is broken
                # B = -1, there is no policy for that service_name or imsi not authorized
                # B = -2, if imsi has already a master key
                connection.send(bytes(str(B), 'utf-8'))


    threading.Thread(target = dh_thread).start()

    # listening for new packets
    # p4runtime_sh.shell.PacketIn()
    packet_in = sh.PacketIn()
    threads = []
    while True:
        #print("[!] Waiting for receive something")

        def handle_thread_pkt_management(packet, threads):
            print("PACKET RECEIVED AT " + str(time.time()))
            packet_handler = threading.Thread(target = packetHandler, args = (packet,))
            threads.append(packet_handler)
            packet_handler.start()
            print("[!] packet_handler started")
            for thread in threads:
                thread.join()

        # we are using a filter for straining the packets escluding the grpc ones from our analysis

        my_filter = "ether proto arp or (ip host 192.168.56.6 and port host 80)"
        # the scapy filter is using the Berkeley Packet Filter https://biot.com/capstats/bpf.html the same one as tcpdump
        # https://stackoverflow.com/questions/37453283/filter-options-for-sniff-function-in-scapy

        # https://github.com/secdev/scapy/blob/246ad3fecbd218e6cd57705b1b42a8a5a0714652/scapy/sendrecv.py#L1307
        # https://github.com/secdev/scapy/blob/246ad3fecbd218e6cd57705b1b42a8a5a0714652/scapy/sendrecv.py#L980
        # scapy.sniff(prn = lambda m: handle_thread_pkt_management(m, threads), filter = my_filter)

        # for the shell.packetIn() there is no filter...
        # https://github.com/p4lang/p4runtime-shell/blob/main/p4runtime_sh/shell.py#L2611
        packet_in.sniff(lambda m: handle_thread_pkt_management(m, threads), timeout = 0.01)

# all the executable is inside the controller function
if __name__ == '__main__':
    controller()