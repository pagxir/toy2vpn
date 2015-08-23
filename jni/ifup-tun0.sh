#!/bin/bash

PATH=${PATH}:/sbin:/usr/sbin

ip6tables -F FORWARD

iptables -t mangle -N TOYVPN
iptables -t mangle -F TOYVPN
iptables -t mangle -A TOYVPN -d 0.0.0.0/8 -j RETURN
iptables -t mangle -A TOYVPN -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A TOYVPN -d 169.254.0.0/16 -j RETURN
iptables -t mangle -A TOYVPN -d 224.0.0.0/4 -j RETURN
iptables -t mangle -A TOYVPN -d 240.0.0.0/4 -j RETURN
iptables -t mangle -A TOYVPN -p udp -j MARK --set-mark 0x30
iptables -t mangle -A TOYVPN -p udp -m owner --uid-owner 0 -j MARK --set-mark 0x0

iptables -t mangle -A TOYVPN -d 10.0.0.0/8 -j RETURN
iptables -t mangle -A TOYVPN -d 172.16.0.0/12 -j RETURN
iptables -t mangle -A TOYVPN -d 192.168.0.0/16 -j RETURN

iptables -t mangle -A TOYVPN -p tcp --dport 9418 -j RETURN
iptables -t mangle -A TOYVPN -p tcp --dport 30007 -j RETURN
iptables -t mangle -A TOYVPN -p tcp --dport 30008 -j RETURN
iptables -t mangle -A TOYVPN -p tcp -j MARK --set-mark 0x30

iptables -F OUTPUT -t mangle
iptables -A OUTPUT -t mangle -p tcp -j TOYVPN
iptables -A OUTPUT -t mangle -p udp --dport 53 -j TOYVPN

tun_dev="tun0";
#phy_dev="usb0";

phy_dev=$(ip -4 addr|sed -n '/eth[0-9]$/s/.*global //p');
phy_addr=$(ip -4 addr|sed -n "/eth[0-9]$/s/.*inet \([0-9.]*\)[ /].*/\1/p")

#tc qdisc add dev ${phy_dev} root handle 10: htb
#tc filter add dev ${phy_dev} parent 10: protocol ip prio 10 u32 match ip dst 172.25.1.51/32 action nat egress ${phy_addr}/32 172.25.1.52
#toyclient -s ./ifup-tun0.sh -t tun0 -r $(ip -4 addr|sed -n "/eth[0-9]$/s/.*inet \([0-9.]*\)[ /].*/\1/p") 172.25.1.51:3389

if ! [ X$1 = X"" ]; then
    tun_dev=$1;
fi;

sysctl -w net.ipv4.conf.all.rp_filter=0;
sysctl -w net.ipv4.conf.${tun_dev}.rp_filter=0;
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.ipv6.conf.default.forwarding=1

ip -4 addr add 10.3.0.1/24 dev ${tun_dev}
ip -6 addr add 2001:c0a8:2b01::1/64 dev ${tun_dev}
ip -6 route add default dev ${tun_dev} metric 256 proto static
ip link set dev ${tun_dev} mtu 1400 up

ip route flush table 30
ip route add 10.3.0.0/24 dev ${tun_dev} table 30 scope link
ip route add default dev ${tun_dev} table 30
ip rule add fwmark 0x30 table 30 pref 999

