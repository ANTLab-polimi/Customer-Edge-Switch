from scapy.all import *
import time
import socket

SELF_MAC = '08:00:27:f8:2e:fb'
BCAST_MAC = 'ff:ff:ff:ff:ff:ff'
iface = "eth1"

packet = Ether(dst = BCAST_MAC, src = SELF_MAC, type = 0x0806)/ARP(psrc = "192.168.56.6", hwsrc = SELF_MAC, pdst = "192.168.56.5")
sendp(packet, iface=iface)

#test "reply" packet
#time.sleep(4)
#packet = Ether(dst=controller_ether)/IP(src="192.169.56.2", dst="192.168.56.1")/TCP(sport=80, dport=1298)
#sendp(packet, iface=iface)