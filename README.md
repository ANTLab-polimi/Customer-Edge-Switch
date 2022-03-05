# Customer Edge Switch (CES)

Development of CES component, that is a programmable switch managed by a specific controller which checks policies on a policy server. 

This way it is possible to perform authentication and authorization processes, in order to open verified connections, implementing a policy-based protocol.


## Installation

git clone this repository:
```
git clone https://github.com/FrancescoBattagin/CES
```

In provision-free5g.sh, Edit: 
* The $INTERFACE variable, pointing to the name of the interface that provides internet connection.
* The root password used by ansible-playbook (within the --extra-vars argument)

To create the complete environment, run:
```
vagrant up
```
The process will take some minutes.

SSH to the free5gc vm:
```
vagrant ssh hydrogen
```

Verify that free5gc containers are running:
```
sudo docker ps
```

Connect to the UE container:
```
sudo docker exec -it ue bash
```

List all the UEs:
```
ifconfig
```

Verify the connection to internet (for example, through oaitun_ue1 interface):
```
ping 8.8.8.8 -I oaitun_ue1
```


## Test authentication and authorization

First of all, it is necessary to set the default gateway of free5gc and dst vms to the specific BMV2 interfaces belonging to the private networks.

SSH to the free5gc vm and set default gw:
```
vagrant ssh hydrogen
sudo route add default gw 192.168.56.2
```

Do the same thing inside dst vm:
```
vagrant ssh helium
sudo route add default gw 192.169.56.4
```

Then the BMV2 switch can be started.
SSH to the BMV2 vm:
```
vagrant ssh release
```

Run BMV2 switch:
```
sudo simple_switch_grpc --log-console --no-p4 --device-id 1 -i 1@eth1 -i 2@eth2 --thrift-port 9090 -- --grpc-server-addr localhost:50051 --cpu-port 255
```

Inside another terminal, run orchestrator:
```
cd CES/orchestrator && sudo python3 orchestrator.py
```
It will wait for incoming packets.


SSH to the free5gc vm:
```
vagrant ssh hydrogen
```

Send a gratuitous ARP to BMV2 vm:
```
cd CES/tests/ && sudo python3 arp_src_test.py
```
Then enter UE container:
```
sudo docker exec -it ue bash
```

Send another gratuitous ARP to controller from dst vm:
```
vagrant ssh helium
cd CES/tests/ && sudo python3 arp_dst_test.py
```

Inside UE container run:
```
sudo python3 udp_tcp_src_test.py
```

This scripts simulates the authentication (a key-exchange through Diffie-Hellman) and authorization process (an authorization packet) between the controller and the UE, who wants to have access to a specific service (whose entrypoint is the IP address of dst vm, and dport is 80).

An "open" entry (which doesn't care about TCP source port) will be installed on the BMV2 switch and, when a "reply" packet from dst will be received, the "open" entry will be substituted by two "strict" entries (traffic is now legitimated from ue to dst and viceversa).

To check if everything is ok and to install the "strict" entries (before controller timeout), it is possible to run netcat on both vms, as follows:
* Inside dst vm run:
	```
	sudo nc -l 0.0.0.0 80
	```
* Inside ue container run:
	```
	sudo nc -p 1298 192.169.56.2 80
	```
Then, try to send a message from ue to the nc server; it will be displayed.
The same will happen if a message is sent from the server. 


## Warning
UE container is unstable. Sometimes UEs' interfaces lose connectivity or they disappear at all.
Just rerun ansible playbook script inside hydrogen vm.
```
sudo ansible-playbook -K Demo2Exp1.yml  -e  "internet_network_interface=<< internet network interface name>>"
```


## External links
* Vagrant5GCluster: [link](https://github.com/EmanueleGallone/Vagrant5GCluster.git)
* Free5gc vm setup scripts: [link](https://github.com/LABORA-INF-UFG/NetSoft2020-Tutorial4-Demo2-Exp1)
