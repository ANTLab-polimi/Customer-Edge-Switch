sudo iptables -A OUTPUT -p tcp --sport 54321 --tcp-flags RST RST -j DROP