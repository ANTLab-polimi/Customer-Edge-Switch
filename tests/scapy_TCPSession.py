#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# link Github: https://gist.github.com/N0dr4x/ffe99618a738978605719ce525a33042

'''
Simple Scapy TCP Session class that provide ability
to : 
   - execute the 3-way handshake (eg. connect)
   - properly close connection (->FIN/ACK, <-FIN/ACK, ->ACK )
   - send automatic acknowledgment of received tcp data packet
   - build a next packet to send with correct sequence number
   - directly send data through the session
HINT : Don't forget to block TCP/RST packet that was send
       by the linux kernel because no source port was bound.
       
        # iptables -A OUTPUT -p tcp --sport 1337 --tcp-flags RST RST -j DROP

-A add a rule at the end of the chain chosen
OUTPUT is the chain chosen
-p tcp stands for the tcp protocol
--sport is the source port
--dport is the destination port
--tcp-flags is the kind of flag
-j ACCEPT/DROP -> take the specified action

WE ARE USING THE SPORT 54321 NOT THE 1337 AS INDICATED IN THE EXAMPLE!!!!!!!!

To delete a particular line in iptables:

    // to prompt onto the terminal all the table with the line numbers
    sudo iptables -L --line-numbers 
    // 
    sudo iptables -D OUTPUT <Number>

Source port is, for now, fixed to 1337 to facilitate wireshark filtering.
The purpose of this class is to easily build a working tcp session and
have complete scapy control of the next tcp packet.
Usage & example :
   
   # Create the session object and connect to host 192.168.13.37 port 80
   >>> sess = TcpSession(('192.168.13.37',80))
   >>> sess.connect()
   # Build next packet and send it fragmented (layer 2)
   >>> p = sess.build('GET / HTTP/1.1\r\n\r\n')
   >>> send(fragment(p, fragsize=16))
   # Direct send data through the session and close
   >>> sess.send('GET /index.html HTTP/1.1\r\n\r\n')
   >>> sess.close()
   # Session object can be reusable
   >>> sess.connect()
   >>> sess.send('GET /robot.txt HTTP/1.1\r\n\r\n')
   >>> sess.close()
TODO :
   1/ Optionally dump received data to a file
   2/ Proper logging
'''

from scapy.all import *
from scapy.contrib.nsh import *
from threading import Thread
from scapy.packet import *
import time
from scapy.sendrecv import *
from scapy.arch.linux import *

class TcpSession:

    def __init__(self,ip_src,ip_dst,sport,dport):
        self.seq = 0
        self.ack = 0
        self.ip = IP(src=ip_src,dst=ip_dst,proto=6)
        self.sport = sport
        self.dport = dport
        self.connected = False
        self._ackThread = None
        self._timeout = 50
        
    def _ack(self, p):
        self.ack = p[TCP].seq + len(p[Raw])
        ack = self.ip/TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        send(ack)

    def _ack_rclose(self):
        self.connected = False

        self.ack += 1
        fin_ack = self.ip/TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
        ack = sr1(fin_ack, timeout=self._timeout)
        self.seq += 1

        assert ack.haslayer(TCP), 'TCP layer missing'
        assert ack[TCP].flags & 0x10 == 0x10 , 'No ACK flag'
        assert ack[TCP].ack == self.seq , 'Acknowledgment number error'
      
    def my_sniff(self):
        pkt = scapy.sendrecv.sniff(iface='enp3s0', filter='tcp and src 192.168.2.2', timeout=10, count=1)
        print(pkt.payload)

    def _sniff(self):
        s = L3RawSocket()
        while self.connected:
            p = s.recv(MTU)
            if p.haslayer(TCP) and p.haslayer(Raw) and p[TCP].dport == self.sport :
                self._ack(p)
            if p.haslayer(TCP) and p[TCP].dport == self.sport and p[TCP].flags & 0x01 == 0x01 : # FIN
                self._ack_rclose()
            
        s.close()
        self._ackThread = None
        print('Acknowledgment thread stopped')

    def _start_ackThread(self):
        self._ackThread = Thread(name='AckThread',target=self._sniff)
        self._ackThread.start()
        
    def connect(self, hash_hex):
        self.seq = random.randrange(0,(2**32)-1)

        presyn = self.ip/TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags='S')
        #syn = NSH(mdtype=2)/NSHTLV(length=len(hmac_hex), metadata=Raw(hmac_hex))/presyn
        #syn = NSH(mdtype=1,nextproto=1,length=len(hmac_hex),context_header=hmac_hex)/presyn
        syn = NSH(mdtype=1,nextproto=1,context_header=hash_hex)/presyn
        #syn.show()

        #nsh_go = time.time()
        # used to test
        syn = Ether(dst="ff:ff:ff:ff:ff:ff")/syn
        # https://scapy.readthedocs.io/en/latest/api/scapy.sendrecv.html
        #syn_ack = srp1(syn, timeout=self._timeout, iface='eth1', filter='tcp')

        # the sr1 didn't give us back the answer (which theoretically WAS CORRECT...)
        # so, we decide to go with a L3RawSocket
        #nsh_go = time.time()
        #print("SENDING NSH : " + str(nsh_go))
        #scapy.sendrecv.send(syn)
        s = L3RawSocket()
        t = AsyncSniffer(iface="enp3s0", filter="src host 192.168.2.2 && src port 80 && (tcp[13] & 0x12) == 0x12  ", opened_socket=s)
        #syn_ack = srp1(syn, timeout=10, iface='enp3s0', filter='src host 192.168.2.2 && src port 80 && tcp')
        t.start()
        #print("sending the syn packet with NSH")
        scapy.sendrecv.sendp(syn, iface='enp3s0')
        # used to test
        
        #s =  conf.L2Socket()
        #s.send(syn)
        # used to test
        syn_ack = t.stop()
        
        #syn_ack = scapy.sendrecv.sniff(iface='enp3s0', filter='tcp and src 192.168.2.2', timeout=10, count=1)
        '''
        print(len(syn_ack))

        if len(syn_ack) > 0:
            for j in syn_ack:
                j.show()
        '''
        #nsh_arrive = syn_ack.time
        #syn_ack = s.sr1(Ether(dst="ff:ff:ff:ff:ff:ff")/syn)
        #print("NSH ACK ARRIVED: " + str(nsh_arrive))
        #print("RTT for syn NO NSH: " + str(nsh_arrive - nsh_go))
        #print("RTT for syn SIIIIIIIIII NSH: " + str(nsh_arrive - nsh_go))
        #syn_ack.show()
        
        print("SEQUENCE NUMBER TO CHECK: " + str(self.seq))
        self.seq += 1

        #assert syn_ack.haslayer(TCP) , 'TCP layer missing'
        out = False
        
        #s.send(syn)
        syn_ack = syn_ack[0]
        if syn_ack.haslayer(TCP):
            if syn_ack[TCP].flags & 0x12 == 0x12:
                if syn_ack[TCP].ack == self.seq:
                    out = True
                else:
                    print('Acknowledgment number error')
                    return
            else:
                print('No SYN/ACK flags')
                return
        else:
            print('TCP layer missing')
            return
            
        #s.close()
        #assert syn_ack[TCP].flags & 0x12 == 0x12 , 'No SYN/ACK flags'
        #assert syn_ack[TCP].ack == self.seq , 'Acknowledgment number error'

        self.ack = syn_ack[TCP].seq + 1
        ack = self.ip/TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags='A', ack=self.ack)
        send(ack)

        self.connected = True
        self._start_ackThread()
        print('Connected')

    def close(self):
        self.connected = False

        fin = self.ip/TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
        fin_ack = sr1(fin, timeout=self._timeout)
        self.seq += 1

        assert fin_ack.haslayer(TCP), 'TCP layer missing'
        assert fin_ack[TCP].flags & 0x11 == 0x11 , 'No FIN/ACK flags'
        assert fin_ack[TCP].ack == self.seq , 'Acknowledgment number error'

        self.ack = fin_ack[TCP].seq + 1
        ack = self.ip/TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq,  ack=self.ack)
        send(ack)

        print('Disconnected')

    def build(self, payload):
        psh = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/payload
        self.seq += len(psh[Raw])
        return psh

    def send(self, payload):
        psh = self.build(payload)
        ack = sr1(psh, timeout=self._timeout)

        assert ack.haslayer(TCP), 'TCP layer missing'
        assert ack[TCP].flags & 0x10 == 0x10, 'No ACK flag'
        assert ack[TCP].ack == self.seq , 'Acknowledgment number error'