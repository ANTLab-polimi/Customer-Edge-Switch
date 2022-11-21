#!/bin/bash

#this interface is the one connecting the vm to Internet.
INTERFACE="'eth1'"

#install basic packages
sudo apt-get update
sudo apt-get install curl git net-tools ansible -y


#clone Netsoft free5gc repo and install
git clone https://github.com/FrancescoBattagin/Customer-Edge-Switch
cd Customer-Edge-Switch/vm
ansible-playbook -K Demo2Exp1.yml  -e  "internet_network_interface=$INTERFACE" --extra-vars "ansible_become_pass=root"

# --- Adding a patch file for the DNS problem in the container of free5gc --- #                                      
sudo cp /home/vagrant/daemon.json /etc/docker
sudo docker restart ue
