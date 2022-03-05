from scapy.all import *
import threading

class Auth(Packet):
    fields_desc = []
    fields_desc.append(StrLenField("service_ip", "10.0.2.15")) #10.0.0.1 as default
    fields_desc.append(StrLenField("method", "imsi")) #imsi as default
    fields_desc.append(StrLenField("authentication", "310170845466094")) #310170845466094 as default
    fields_desc.append(StrLenField("port", 80)) #80 as default
    fields_desc.append(StrLenField("protocol", "TCP")) #TCP as default
    
    #pkt_ip = IP()
    #if pkt_ip.src == '10.0.2.15': #interface enp0s3
        #fields_desc.append(StrLenField("authentication", "10.0.2.15", bin(len("10.0.2.15"))))
        #fields_desc.append(StrLenField("imsi","310170845466094",1111))
    #else:
        #fields_desc.append(StrLenField("method", "imsi", bin(len("imsi"))))
        #fields_desc.append(StrLenField("imsi","5021301234567894", 1111))

def receive():
    while True:
        packets = None
        packets = sniff(timeout=5)
        packetHandler(packets)

def packetHandler(packets):
    for pkt in packets:
        print("[!] Packets received")
        #pkt_payload = packet.payload
        
        if pkt.getlayer(IP) != None:
            pkt_src = pkt.getlayer(IP).src
            pkt_dst = pkt.getlayer(IP).dst
        
        pkt_ip = pkt.getlayer(IP)
        pkt_imsi = pkt.getlayer(Auth)

        print(packet.getlayer('IP').src)
        print(packet.getlayer('IP').dst)
        print(packet.getlayer('Auth').method)
        print(packet.getlayer('Auth').authentication)
        print(packet.getlayer('UDP').dport)


#print(IP().show())
#print(TCP().show())
#print(UDP().show())
#print(Auth().show())

#test_pkt_tag = Auth(imsi = 310170845466094)
#test_pkt_ip = IP(ttl=100)
#test_pkt_ip.dst = '8.8.8.8'
#print(test_pkt_ip.src)
#print(test_pkt_ip.dst)
#print(test_pkt_tag.imsi) #ok -> imsi set inside mytag layer

#print("\n\n\n\n\n\nnow test w/ a packet")

packet = IP(ttl = 100, dst = '10.0.2.15')/UDP(dport=53)/Auth(service_ip = "10.0.0.2", method = "imsi", authentication = "5021301234567894", port = 25, protocol = "UDP")
#packet = IP(ttl = 100, dst = '10.0.2.15')/UDP(dport=54)/Auth(service_ip = "10.0.0.3", method = "ip", authentication = "10.0.0.250", port = 26, protocol = "TCP")
#packet = IP(ttl = 100, dst = '10.0.2.15')/UDP(dport=55)/Auth(service_ip = "10.0.0.4", method = "token", authentication = "abcdefghilmnopqrstuvz", port = 26, protocol = "TCP")

receiver = threading.Thread(target = receive)
receiver.start()

send(packet)