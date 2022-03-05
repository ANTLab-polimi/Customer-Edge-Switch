import subprocess
#from scapy.all import *

history = {}
#{imsi1: [{ip: ip1, port: port1}, {ip: ip2, port: port2}, imsi2: [{ }, { }],...}

class MyTag(Packet):
    name = "IMSI"
    fields_desc = []
    fields_desc.append(StrLenField("imsi","310170845466094",1111))

def redirect():
    tcpdump = subprocess.Popen("tcpdump -nn", stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    while True:
        found = False
        s = tcpdump.stdout.readline()
        print(s)
        s.split(" ")
        #timestamp IP src.port > dst.port
        src_addr = s[2]
        tmp = src.split(".")
        sport = tmp[4]
        src = ip_assembler(src_addr)
        dst_addr = s[4] #check
        tmp = dst_addr.split(".")
        dport = tmp[4] #fix
        ip = ip_assembler(dst_addr)
        imsi = "310170845466094" #retrieve imsi (?)
        
        #if tcp protocol
        if imsi in history:
            for dictionary in history[imsi]:
                if dictionary["ip"] == ip and dictionary["port"] == dport:
                    found = True
                    break
            if not found:
                history[imsi].append({'ip': ip, 'port': dport})
                portKnocking(imsi, ip, dport)
        else:
            history[imsi] = []
            history[imsi].append({'ip': ip, 'port': dport})
            portKnocking(imsi, ip, dport)

        #print(history)

def portKnocking(imsi, ip, dport):
    packet = IP(ttl = 100, dst = ip)/UDP(dport = dport)/MyTag(imsi = imsi)
    send(packet)


def ip_assembler(ip_and_port):
    s = ip_and_port.split(".")
    ip = s[0] + "." + s[1] + "." + s[2] + "." + s[3]
    return ip

redirect()