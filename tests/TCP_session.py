from threading import Thread
from queue import *
from scapy.all import *
from scapy.contrib.nsh import *
from scapy.packet import *
from scapy.sendrecv import *
from scapy.arch.linux import *

m_iface = "enp3s0"
m_finished = False
m_dst = "192.168.2.2"
m_ip = "192.168.1.1"
m_sport = 54321
m_dport = 80
m_protocol = "tcp"

class TCP_Session:

    def __init__(self,ip_src,ip_dst,sport,dport,iface):

        global m_iface
        global m_dst
        global m_ip
        global m_sport
        global m_dport
        global m_protocol

        self.seq = 0
        self.ack = 0
        if ip_src == None or ip_dst == None:
            self.ip = IP(src=m_ip,dst=m_dst,proto=6)
        else:
            self.ip = IP(src=ip_src,dst=ip_dst,proto=6)
        if sport == None:
            self.sport = m_sport
        else:
            self.sport = sport
        if dport == None:
            self.dport = m_dport
        else:
            self.dport = dport
        if iface == None:
            self.iface = m_iface
        else:
            self.iface = iface
        self.connected = False
        self._ackThread = None
        self._timeout = 10
        self.q = Queue()
        self.pre_ack = 0
        self.pre_seq = 0

    # for debugging purpose
    def print_summary(pkt):
        print(pkt.summary())

    # to send an ack packet answering
    def _ack(self, p):
        self.ack = p[TCP].seq #+ len(Raw(p))
        ack = self.ip/TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        send(ack, iface=self.iface)

    # to send a fin ack answering to the fin packet of the server due to a remote closing session
    def _ack_rclose(self):
        self.connected = False

        self.ack += 1
        fin_ack = self.ip/TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
        send(fin_ack, iface=self.iface)
        self.seq += 1

        # waiting for the ack 
        out = False
        while(not out):
            try:
                ack = self.q.get(block=True, timeout=self._timeout)

                if ack[TCP].flags & 0x10 == 0x10:
                    if ack[TCP].ack == self.seq:
                       out = True
                    else:
                        print('[DISCONNECTION] Acknowledgement number error')
                else:
                    print('No SYN/ACK flag')
            except Empty:
                pass
    
    # the target for the sniffing thread
    def threaded_sniff_target(self):
        global m_finished
        global m_dst
        global m_protocol
        
        while (not m_finished):
            sniff(iface = m_iface, filter= str(m_protocol) + " && src host " + str(m_dst) + " && src port " + str(self.dport), prn = lambda x : self.q.put(x))
    
    # launching the sniff as a thread and returning it back in order to control it
    # it has to be launched BEFORE any send function to avoid to lose the packets
    def threaded_sniff(self):

        sniffer = Thread(target = self.threaded_sniff_target, args = ())
        sniffer.daemon = True
        sniffer.start()

        return sniffer
    
    # here the TCP three-way handshake is handled 
    def connect(self, hash_hex):
        # extracting a random number for the sequence number of the packet
        self.seq = random.randrange(0, (2**32)-1)

        # creating the first packet with the authorisation header
        presyn = self.ip/TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags='S')
        syn = NSH(mdtype=1, nextproto=1, context_header=hash_hex)/presyn
        final_syn = Ether(dst="ff:ff:ff:ff:ff:ff")/syn

        # sending the packet at layer 2
        sendp(final_syn, self.iface)
        self.seq += 1
        # waiting for the syn ack 
        out = False
        while(not out):
            try:
                syn_ack = self.q.get(block=True, timeout=self._timeout)

                if syn_ack[TCP].flags & 0x12 == 0x12:
                    if syn_ack[TCP].ack == self.seq:
                       out = True
                    else:
                        print('[CONNECT] Acknowledgement number error')
                else:
                    print('No SYN/ACK flag')
            except Empty:
                pass 

        #sending the third packet of the handshake
        self.ack = syn_ack[TCP].seq + 1
        ack = self.ip/TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags='A', ack=self.ack)
        send(ack, iface=self.iface)

        self.connected = True
        print('Connected')

    # to build a generic packet with a payload
    def build(self, payload):
        psh = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/payload
        #print('Lenght of the packet: ' + str(len(psh)))
        #print('SEQ number before: ' + str(self.seq))
        self.pre_seq = self.seq
        self.seq += len(payload)
        #print('SEQ number after: ' + str(self.seq))
        return psh

    #to close the connection with the server
    def close(self):
        self.connected = False

        fin = self.ip/TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
        send(fin, iface=self.iface)
        self.seq += 1

        # waiting for the fin ack 
        out = False
        while(not out):
            try:
                fin_ack = self.q.get(block=True, timeout=self._timeout)

                if fin_ack[TCP].flags & 0x11 == 0x11:
                    if fin_ack[TCP].ack == self.seq:
                       out = True
                    else:
                        print('[CLOSE] Acknowledgement number error')
                else:
                    print('No FIN/ACK flag')
            except Empty:
                pass
        
        self.ack = fin_ack[TCP].seq + 1
        ack = self.ip/TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq,  ack=self.ack)
        send(ack, iface=self.iface)

        print('Disconnected')

    def send_data(self, data):

        #TODO encoding with JSON format the data to send
        # for the moment, we will send the test message like a padding header (Raw)
        #print('data lenght: ' + str(len(data)))
        payload = Raw(data)
        #print('payload lenght: ' + str(len(payload)))
        pkt = self.build(payload)
        send(pkt, iface=self.iface)

        # waiting for the ack
        out = False
        while(not out):
            try:
                ack = self.q.get(block=True, timeout=self._timeout)

                if ack[TCP].flags & 0x10 == 0x10:
                    if ack[TCP].ack == self.seq:
                       out = True
                    else:
                        print('[SEND_DATA] Acknowledgement number error')
                        print('ACK number: ' + str(ack[TCP].ack) )
                        print('SEQ number: ' + str(self.seq))
                        print(ack.summary())
                else:
                    print('No ACK flag')
            except Empty:
                print('[SEND_DATA] timeout queue')
                pass