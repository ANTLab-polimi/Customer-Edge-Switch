#!/usr/bin/python
"""
This is the most simple example to showcase Containernet.
"""
from mininet.net import Containernet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from subprocess import Popen, PIPE
import time
setLogLevel('info')

net = Containernet(controller=Controller)
info('*** Adding docker containers\n')
ue1 = net.addDocker("ue1", ip='192.187.3.251', dimage="laboraufg/ue-openairsim", cap_add = ["NET_ADMIN"], ports=[1295], port_bindings={1295:1295}, publish_all_ports=True)
ue2 = net.addDocker("ue2", ip='192.187.3.252', dimage="laboraufg/ue-openairsim", cap_add = ["NET_ADMIN"], ports=[1296], port_bindings={1296:1296}, publish_all_ports=True)
ue3 = net.addDocker("ue3", ip='192.187.3.254', dimage="laboraufg/ue-openairsim", cap_add = ["NET_ADMIN"], ports=[1297], port_bindings={1297:1297}, publish_all_ports=True)
enb = net.addDocker("enb", ip='192.187.3.253', dimage="laboraufg/enb-openairsim", cap_add = ["NET_ADMIN"])

upf = net.addDocker("upf", ip='192.187.3.6', devices=["/dev/net/tun:/dev/net/tun"], dimage="laboraufg/free5gc-st1", cap_add = ["NET_ADMIN"], ports = [1234], port_bindings = {1234:1234})
smf = net.addDocker("smf", ip='192.187.3.3', dimage="laboraufg/free5gc-st1")
amf = net.addDocker("amf", ip='192.187.3.2', dimage="laboraufg/free5gc-st1")
hss = net.addDocker("hss", ip='192.187.3.4', dimage="laboraufg/free5gc-st1")
pcrf = net.addDocker("pcrf", ip='192.187.3.5', dimage="laboraufg/free5gc-st1")

controller = net.addDocker('controller', ip='192.187.3.7', build_params={"dockerfile":"Dockerfile", "path":"../../p4runtime-shell/"})
endpoint = net.addDocker('endpoint', ip='192.187.3.9', dimage="ubuntu:trusty", ports=[1290], port_bindings={1290:1290}, publish_all_ports=True)

#not needed if addP4Switch (see below)
#d1 = net.addDocker('bmv2', ip='192.187.3.8', dimage="opennetworking/p4mn")

#created inside ansible-playbook
#d1 = net.addDocker("mongodb-svc", ip='192.187.3.100', dimage="laboraufg/mongodb-free5gc")
#d7 = net.addDocker("webui", ip='192.187.3.101', dimage="laboraufg/webui-free5gc", ports=[3000], port_bindings={3000:3000})

info('*** Adding controller\n')
net.addController('c0')

info('*** Creating switches\n')
s1 = net.addSwitch('s1')
s2 = net.addSwitch('s2')
s3 = net.addSwitch('s3')
s4 = net.addSwitch('s4')
s5 = net.addSwitch('s5')
#s6 = net.addSwitch('s6')
#s7 = net.addSwitch('s7')
#s8 = net.addSwitch('s8')
#s9 = net.addSwitch('s9')
#s10 = net.addSwitch('s10')
#s11 = net.addSwitch('s11')
#s12 = net.addSwitch('s12')
bmv2 = net.addP4Switch(name='bmv2', json="../../CES/p4-test.json", loglevel='debug', pktdump=False)

info('*** Creating links\n')
net.addLink(ue1, s1)  #ue1 -> s1
net.addLink(ue2, s1) #ue2 -> s1
net.addLink(ue3, s1) #ue3 -> s1
net.addLink(s1, s2, cls=TCLink, delay='100ms', bw=1)
net.addLink(enb, s2) #enb -> s2

#If core part has only one switch
net.addLink(upf, s5, params1 = {"ip": "192.187.3.60/8"}) #add another interface w\ specified ip address
net.addLink(smf, s5)
net.addLink(pcrf, s5)
net.addLink(amf, s5)
net.addLink(hss, s5)


#If every core container is linked w\ specific other containers; need to add new interfaces?
#net.addLink(enb, s3, params1={"ip": "192.187.3.250/8"}) 
#net.addLink(s3, s4, cls=TCLink, delay='100ms', bw=1)
#net.addLink(upf, s4) #s4 -> upf

#net.addLink(upf, s5) #s5 -> upf
#net.addLink(s5, s6, cls=TCLink, delay='100ms', bw=1)
#net.addLink(smf, s6) #s6 -> smf

#net.addLink(smf, s7) #smf -> s7
#net.addLink(s7, s8, cls=TCLink, delay='100ms', bw=1) #s5 -> s6
#net.addLink(s8, pcrf) #s8 -> pcrf

#net.addLink(smf, s9) #smf -> s9
#net.addLink(s9, s10, cls=TCLink, delay='100ms', bw=1) #s7 -> s8
#net.addLink(amf, s10) #s10 -> amf

#net.addLink(amf, s11) #amf -> s11
#net.addLink(s11, s12, cls=TCLink, delay='100ms', bw=1) #s9 -> s10
#net.addLink(hss, s12) #s12 -> hss


net.addLink(upf, bmv2, params1 = {"ip": "192.187.3.61/8"}) #upf -> bmv2
net.addLink(controller, bmv2) #bmv2 -> controller
net.addLink(bmv2, endpoint) #bmv2 -> endpoint


info('*** Starting network\n')
net.start()
net.staticArp() #to avoid components' ARP requests/replies

info('*** Running CLI\n')
#Some useful packages to be installed
#commands_d1 = "sudo docker exec -it mn.ue1 apt-get install -y tcpdump && sudo docker exec -it mn.ue2 apt-get install -y tcpdump && sudo docker exec -it mn.ue3 apt-get install -y tcpdump"
#commands_smf = "sudo docker exec -it mn.endpoint apt-get install -y tcpdump"
#commands_upf = "sudo docker exec -it mn.controller apt-get install -y git && sudo docker exec -it mn.controller git clone https://github.com/FrancescoBattagin/CES && sudo docker exec -it mn.controller apt-get -y install vim"
#commands_upf_2 = "sudo docker exec -it mn.controller apt-get update && sudo docker exec -it apt-get install -y python3-pip && sudo docker exec -it mn.controller pip3 install p4runtime-shell && sudo docker exec -it mn.controller pip3 scapy && sudo docker exec -it mn.controller pip3 pyyaml && sudo docker exec -it mn.controller pip3 inotify"
#bash_commands = Popen(commands_d1, shell = True, stdout = PIPE)
#time.sleep(5)
#bash_commands = Popen(commands_smf, shell = True, stdout = PIPE)
#time.sleep(5)
#bash_commands = Popen(commands_upf, shell = True, stdout = PIPE)
#time.sleep(20)
CLI(net)

info('*** Stopping network')
net.stop()