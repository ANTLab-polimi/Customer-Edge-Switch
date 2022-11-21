#!/bin/bash

# Print script commands and exit on errors.
set -xe

# --- Mininet --- #
if [ ! -e mininet ]; then
	git clone https://github.com/mininet/mininet mininet
fi
cd mininet
PATCH_DIR="${HOME}/patches"
patch -p1 < "${PATCH_DIR}/mininet-dont-install-python2.patch" || echo "Errors while attempting to patch mininet, but continuing anyway ..."
cd ..

# TBD: Try without installing openvswitch, i.e. no '-v' option, to see
# if everything still works well without it.
sudo ./mininet/util/install.sh -nw

find /usr/lib /usr/local $HOME/.local | sort > $HOME/usr-local-7-after-mininet-install.txt

# --- Tutorials --- #
if [ ! -e /home/p4/tutorials ]; then
	git clone https://github.com/p4lang/tutorials
	sudo mv tutorials /home/p4
fi
sudo chown -R p4:p4 /home/p4/tutorials

# --- Emacs --- #
if [ ! -e /home/p4/.emacs.d/ ]; then
	sudo cp /home/vagrant/p4_16-mode.el /usr/share/emacs/site-lisp/
	sudo mkdir /home/p4/.emacs.d/
	echo "(autoload 'p4_16-mode' \"p4_16-mode.el\" \"P4 Syntax.\" t)" > init.el
	echo "(add-to-list 'auto-mode-alist '(\"\\.p4\\'\" . p4_16-mode))" | tee -a init.el
	sudo mv init.el /home/p4/.emacs.d/
	sudo ln -s /usr/share/emacs/site-lisp/p4_16-mode.el /home/p4/.emacs.d/p4_16-mode.el
fi
sudo chown -R p4:p4 /home/p4/.emacs.d/

# --- Vim --- #
cd ~
if [ ! -e .vim ]; then
	mkdir .vim
fi
cd .vim
if [ ! -e ftdetect ]; then
	mkdir ftdetect
fi
if [ ! -e syntax ]; then
	mkdir syntax
fi
echo "au BufRead,BufNewFile *.p4      set filetype=p4" >> ftdetect/p4.vim
echo "set bg=dark" >> ~/.vimrc
sudo mv ~/.vimrc /home/p4/.vimrc
sudo cp ~/p4.vim syntax/p4.vim
cd ~
if [ ! -e /home/p4/.vim ]; then
	sudo mv .vim /home/p4/.vim
fi
sudo chown -R p4:p4 /home/p4/.vim
sudo chown p4:p4 /home/p4/.vimrc

# --- Adding a patch file for the DNS problem in the container of free5gc --- #
#sudo cp /home/vagrant/daemon.json /etc/docker

# --- Adding Desktop icons --- #
DESKTOP=/home/${USER}/Desktop
mkdir -p ${DESKTOP}

cat > ${DESKTOP}/Terminal.desktop << EOF
[Desktop Entry]
Encoding=UTF-8
Type=Application
Name=Terminal
Name[en_US]=Terminal
Icon=konsole
Exec=/usr/bin/x-terminal-emulator
Comment[en_US]=
EOF

cat > ${DESKTOP}/Wireshark.desktop << EOF
[Desktop Entry]
Encoding=UTF-8
Type=Application
Name=Wireshark
Name[en_US]=Wireshark
Icon=wireshark
Exec=/usr/bin/wireshark
Comment[en_US]=
EOF

sudo mkdir -p /home/p4/Desktop
sudo mv /home/${USER}/Desktop/* /home/p4/Desktop
sudo chown -R p4:p4 /home/p4/Desktop/

# Do this last!
sudo reboot
