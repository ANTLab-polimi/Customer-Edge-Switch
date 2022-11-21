# Customer Edge Switch (CES)

Development of CES component, that is a programmable switch managed by a specific controller which checks policies on a policy server. 

This way it is possible to perform authentication and authorization processes, in order to open verified connections, implementing a policy-based protocol.


## Installation

git clone this repository:
```
git clone https://github.com/ANTLab-polimi/Customer-Edge-Switch.git
```

In vm/provision-free5g.sh, Edit: 
* The $INTERFACE variable, pointing to the name of the interface that provides internet connection.
* The root password used by ansible-playbook (within the --extra-vars argument)

To create the complete environment, run:
```
cd vm && vagrant up
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

Verify the connection to internet (for example, through eth1 interface):
```
ping 8.8.8.8 -I eth1
```

Verify the DNS resolution:
```
ping google.com -I eth1
```

Install p4runtime-shell, inotify and scapy modules inside BMV2 vm:
```
sudo pip3 install p4runtime-shell inotify scapy
```

Install pip3 and scapy module inside dst (helium) vm:
```
sudo apt-get install -y python3-pip --fix-missing
sudo pip3 install scapy
```

Install scapy module inside src (hydrogen) vm:
```
sudo pip3 install scapy
```

Finally, git clone this repository in each vm:
```
git clone https://github.com/ANTLab-polimi/Customer-Edge-Switch.git
```

## Test authentication and authorization

First, it is necessary to set the IP addresses and the default gateway of free5gc (hydrogen) and dst (helium) vms to the specific BMV2 interfaces (release vm) belonging to the private networks.

In the Vagrantfile we have set up two private networks: one for the hydrogen-release and the second for the release-helium.
In this way, we have client and server in two different network emulating a situation as closer as possible to the reality.

Inside the directory Customer-Edge-Switch/vm, we need to connect towards SSH to the free5gc vm, setting the IP address and then setting the default gateway:
```
vagrant ssh hydrogen
sudo ip addr add 192.168.56.1/30 dev eth1
sudo ip link set eth1 up
sudo ip route add default via 192.168.56.2
```

Do the same thing inside dst vm:
```
vagrant ssh helium
sudo ip addr add 192.168.56.6/30 dev eth1
sudo ip link set eth1 up
sudo ip route add default via 192.168.56.5
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
cd Customer-Edge-Switch/orchestrator && sudo python3 orchestrator.py
```
It will wait for incoming packets.
Now we will start the protocol comunication!

SSH to the free5gc vm:
```
vagrant ssh hydrogen
```

Send a gratuitous ARP to BMV2 vm from hydrogen vm:
```
cd Customer-Edge-Switch/tests/ && sudo python3 arp_src_test.py
```

Then enter UE container and start it displaying a bash to interact with it:
```
sudo docker exec -it ue bash
```

Send another gratuitous ARP to controller from dst (helium) vm:
```
vagrant ssh helium
cd Customer-Edge-Switch/tests/ && sudo python3 arp_dst_test.py
```

Inside UE container run:
```
sudo python3 authen_author_src_test.py
```

This scripts simulates the authentication (a key-exchange through Diffie-Hellman, with diffie_hellman_ue.py script) and authorization process between the controller and the UE, who wants to have access to a specific service (whose entrypoint is the IP address of dst vm, and dport is 80).

An "open" entry (which doesn't care about TCP source port) will be installed on the BMV2 switch and, when a "reply" packet (SYN-ACK) from dst will be received, the "open" entry will be substituted by two "strict" entries (traffic is now legitimated from ue to dst and viceversa).
To check if everything is ok, authen_author_src_test.py script sends also a test.txt file to dst.
To generate it, inside UE container run:
```
dd if=/dev/zero of=test.txt count=1024 bs=1024
```

## Warning
UE container is unstable. Sometimes UEs' interfaces lose connectivity or they disappear at all.
Just rerun ansible playbook script inside hydrogen vm.
```
sudo ansible-playbook -K Demo2Exp1.yml  -e  "internet_network_interface=<< internet network interface name>>"
```


After some recreations of the environment, apt cache can give some problems; in those case, it it possible to 
```
sudo apt-get clean
```
and to change those tasks inside Demo2Exp1.yaml ansible playbook with
```
update_cache: yes
```
in
```
update_cache: no
```


## External links
* Vagrant5GCluster: [link](https://github.com/EmanueleGallone/Vagrant5GCluster.git)
* Free5gc vm setup scripts: [link](https://github.com/LABORA-INF-UFG/NetSoft2020-Tutorial4-Demo2-Exp1)
