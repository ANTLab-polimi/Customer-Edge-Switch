# Customer Edge Switch (CES)

Development of CES component, that is a programmable switch managed by a specific controller which checks policies on a policy server.

With this element it is possible to perform authentication and authorization processes, in order to open verified connections, implementing a policy-based protocol.

To test this building block, a Non Intrusive Load Monitoring application between the client (5G machine) and the server (MEC machine) was designed as example of a possible real application.

This project in association with [CHIMA](https://github.com/ANTLab-polimi/CHIMA) is part of a larger project called [AI-SPRINT](https://www.ai-sprint-project.eu/).


## Installation


### on physical machines

We have tested this environment on three physical machines.

The first one stands for the 5G network, the second contains the controller and the P4 switch and the last one is conceived as a MEC node where the computation takes hold.

All the machine had these characteristics:

* CPU: Intel Core i5-8400 at 2.80GHz with 6 cores
* RAM: 32 GB
* OS: Ubuntu 22.04.2 LTS

and they were collocated inside the same LAN.

Clone this repository in every machine:
```
git clone https://github.com/ANTLab-polimi/Customer-Edge-Switch.git
```

In the machine where will be simulated the 5G network (the first one) you need to install scapy and pandas python libraries:
```
sudo pip3 install scapy pandas
```

In the central machine it is required to install inotify, scapy and the p4runtime-shell libraries:
```
sudo pip3 install p4runtime-shell inotify scapy
```
Moreover, you need to install the BMv2 switch.
The official repository on GitHub about the BMv2 switch is [this](https://github.com/p4lang/behavioral-model) and the repository of the P4 compiler is [here](https://github.com/p4lang/p4c).

Also in the third one (MEC node) there is the need of installing additional python libraries:
```
sudo pip3 install pandas dash plotly
```

As last step, you need to install the 5G emulator:

1.  Clone the [repository of free5Gc](https://github.com/LABORA-INF-UFG/NetSoft2020-Tutorial4-Demo2-Exp1)
2.  Install Ansible:
```
sudo apt -y install ansible
```
3.  Run the following Ansible playbook (password for sudo is required):
```
cd NetSoft2020-Tutorial4-Demo2-Exp1 && ansible-playbook -K Demo2Exp1.yml  -e  "internet_network_interface=<< internet network interface name>>"
```
NB: you retrieve your *internet network interface* name with the command `ifconfig`.


Now, verify that free5gc containers are running on the first machine:
```
sudo docker ps
```

If its are not running, you need to restart all the containers with the follow command and check again if its are up now:
```
sudo docker restart ue enb webui pcrf hss smf upf amf mongodb-svc
```

Connect to the UE container:
```
sudo docker exec -it ue bash
```

List all the UEs:
```
ifconfig
```

Verify the connection to internet:
```
ping 8.8.8.8 -I <your-internet-interface>
```

Verify the DNS resolution:
```
ping google.com -I <your-internet-interface>
```

Now you need to download the HIPE dataset inside the UE container checking [this page of the NILM repository on GitHub](https://github.com/nilmtk/nilmtk/tree/master/nilmtk/dataset_converters/hipe). You can download the [1 week version](https://www.ipd.kit.edu/mitarbeiter/hipe/hipe_cleaned_v1.0.1_geq_2017-10-23_lt_2017-10-30.zip) or the [1 month version](https://www.ipd.kit.edu/mitarbeiter/hipe/hipe_cleaned_v1.0.1_geq_2017-10-01_lt_2018-01-01.zip), it is not relevant for the test.

Then you need to copy also the `demo_client.py` inside the UE container from the host with this command:
```
sudo docker cp ~/Customer-Edge-Switch/tests/demo_client.py <UE_container_id>:/demo_client.py
``` 
and modify the 15th line of code:
```
file_to_send = "path/to/the/name_of_file_downloaded_before.csv"
```

At this point the installation part is completed!

### on Virtual Machines

You can also install all environment in just one machine by leveraging the VMs.
We have used Vagrant as hypervisor for the VMs.

So, before going ahead, you need to install Vagrant on your pc following the instruction on the [Vagrant web page](https://developer.hashicorp.com/vagrant/downloads).

The three machines are:

free5gc vm -> the hydrogen vm (first)
BMv2 vm (second)
MEC vm -> the helium vm (third)

Clone this repository in your machine:
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

If its are not running, you need to restart all the containers with the follow command and check again if its are up now:
```
sudo docker restart ue enb webui pcrf hss smf upf amf mongodb-svc
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

Install p4runtime-shell, inotify and scapy modules inside the second (BMv2) vm:
```
sudo pip3 install p4runtime-shell inotify scapy
```

Install pip3 and various module inside the third (helium) vm:
```
sudo apt-get install -y python3-pip --fix-missing
sudo pip3 install pandas dash plotly
```

Install scapy and pandas module inside the first (hydrogen) vm:
```
sudo pip3 install scapy pandas
```

There is no need to clone this repository in each vm, because all the vm can see the updates done on the repository thanks to the shared folder option of Vagrant.

Now you need to download the HIPE dataset inside the UE container checking [this page of the NILM repository on GitHub](https://github.com/nilmtk/nilmtk/tree/master/nilmtk/dataset_converters/hipe). You can download the [1 week version](https://www.ipd.kit.edu/mitarbeiter/hipe/hipe_cleaned_v1.0.1_geq_2017-10-23_lt_2017-10-30.zip) or the [1 month version](https://www.ipd.kit.edu/mitarbeiter/hipe/hipe_cleaned_v1.0.1_geq_2017-10-01_lt_2018-01-01.zip), it is not relevant for the test.

Then you need to copy also the `demo_client.py` inside the UE container from the first VM with this command:
```
sudo docker cp ~/Customer-Edge-Switch/tests/demo_client.py <UE_container_id>:/demo_client.py
``` 
and modify the 15th line of code:
```
file_to_send = "path/to/the/name_of_file_downloaded_before.csv"
```

At this point the installation part is completed!

## Test authentication and authorization

The Discovery phase of the protocol is out-of-band and it will not be considered in this test. So, we have considered that the user's device and the policy server have already known the service name, service IP address and the service port.

### on physical machines

In the central machine we need to activate the P4 switch and the controller.
The command line for the switch is:

```
sudo simple_switch_grpc --log-console --no-p4 --device-id 1 -i 1@<your_first_interface> -i 2@<your_second_interface> -- --grpc-server-addr 0.0.0.0:50051 --cpu-port 255
```

We cannot start the controller without sconify it because it could run in a different environment (thanks to the SDN paradigm).
Therefore, the command line to sconify the controller is:
```
sudo docker run --rm -it $MOUNT_SGXDEVICE -v "$PWD":/usr/src/myapp -w /usr/src/myapp -e SCONE_HEAP=256M -e SCONE_MODE=sim -e SCONE_ALLOW_DLOPEN=2 -e SCONE_ALPINE=1 -e SCONE_VERSION=1 <your_version_of_scone__docker_image> sh
```

The controller requires to know all the IP-MAC address pairs. Therefore, we need to simulate a IPv6 Router Solicitation with two pings: one from the first machine and the second ping from the third one.

After that, we can start the server and the data visualization script in the third machine.


Also inside the third machine we need to sconify the server application for the same reason of the central machine but here we are required to expose the port number 80, allowing the access to the service from the outside:
```
sudo docker run --rm -it $MOUNT_SGXDEVICE -v "$PWD":/usr/src/myapp -w /usr/src/myapp -e SCONE_HEAP=256M -e SCONE_MODE=sim -e SCONE_ALLOW_DLOPEN=2 -e SCONE_ALPINE=1 -e SCONE_VERSION=1 -p 80:80 <your_version_of_scone__docker_image> sh
```

In order to visualize the result, we raise up also a server as a front-end part:
```
python3 web_app.py
```
then open a browser page and text:
```
http://localhost:8050
```

We are able to see the result written by the application inside the scone container thanks to the permission of the container (for sake of simplicity we have not encrypted the excel file, but in a real context it should be encrypted applying a key exchanged previously between the container itself and the host).

Now we are required to start the key exchange between the client and the server, so in the client machine:
```
sudo python3 diffie_hellman_ue.py
```

At this moment, we need to activate the nfqueue script as well as to execute the UE container in the client:
```
sudo python3 nfqueue_test.py
```

now the container:
```
sudo docker exec -it ue bash
```
and inside the container:
```
python3 demo_client.py
```

From here, the authorization protcol is executed and the client is connected to : 

* The UE is sending the first packet of the three-way handshake TCP connection
* The connection filter is injecting the authorization token inside the packet sending it


**TO BE FINISHED**

### on Virtual Machines

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

**TO BE FINISHED**

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

## How to retrieve the SCONE image to sconify the controller and the server

Where the docker image of scone has to be retrieved from the [SCONE web site](https://sconedocs.github.io/). In particular, our version was obtained from the docker image specialized for the Python language in an [old repository](https://github.com/scontain/hello-world-python) with the addition of some libraries.
An alternative way could be found also in the SCONE web site for the [Python language](https://sconedocs.github.io/Python/).

The addition of the libraries involved these steps:
```
apk update
apk upgrade

# to install the C compiler due to SCONE is using cython to build a python program
apk add make automake gcc g++ subversion python3-dev

# to allow the controller and the server to run inside the container
python3 -m pip install --upgrade setuptools
pip3 install --no-cache-dir --force-reinstall -Iv grpcio
pip3 install p4runtime-shell
pip3 install scapy
pip3 install pyyaml
pip3 install inotify
pip3 install pandas
pip3 install dash
pip3 install plotly
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

## General problems with Docker

It could happen that it will warn you with this error **Docker: Error Response From Daemon: cgroups: cgroup mountpoint does not exist: unknown**.
The solution is mounting the cgroup and then run your docker command:
```
sudo mkdir /sys/fs/cgroup/systemd
sudo mount -t cgroup -o none,name=systemd cgroup /sys/fs/cgroup/systemd
<<your docker run>>
```

Another problem could be correlated to the apt-key deprecation warning, in particular the error is **Key is stored in legacy trusted.gpg keyring**. There is a workaround for this:
```
sudo cp /etc/apt/trusted.gpg /etc/apt/trusted.gpg.d
sudo apt update
```
In this way you are copying the previous file in a directory resolving the conflict.

## External links
* Vagrant5GCluster: [GitHub repository](https://github.com/EmanueleGallone/Vagrant5GCluster.git)
* Free5gc vm setup scripts: [GitHub repository](https://github.com/LABORA-INF-UFG/NetSoft2020-Tutorial4-Demo2-Exp1)
* NILMTK: Non-Intrusive Load Monitoring Toolkit: [GitHub repository](https://github.com/nilmtk/nilmtk)
* SCONE container web page: [web page of SCONE for Python applications](https://sconedocs.github.io/Python/)
* HIPE: An Energy-Status-Data Set from Industrial Production: [paper on the HIPE dataset](https://dl.acm.org/doi/10.1145/3208903.3210278)