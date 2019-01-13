#!/bin/sh
# Bash script for Linux 2.4.x and iptables
# Automates the configuration of a host based firewall
#

# Define Variables Used
iptables=/sbin/iptables
ip6tables=/sbin/ip6tables
pub_int=ens4

# Load Modules
/sbin/depmod -a

# Load required modules
/sbin/modprobe ip_tables
/sbin/modprobe ip_conntrack
/sbin/modprobe iptable_filter
/sbin/modprobe iptable_mangle
/sbin/modprobe iptable_nat
/sbin/modprobe ipt_LOG
/sbin/modprobe ipt_limit
/sbin/modprobe ipt_state

# User Notification Message Starting Script
clear
echo "Initializing IP Firewall settings"

        # Disable routing
            echo 0 > /proc/sys/net/ipv4/ip_forward

        # Reset IPv4
            $iptables -F
            $iptables -X
            $iptables -Z

        # Reset IPv6
            $ip6tables -F
            $ip6tables -X
            $ip6tables -Z

        # Reset Nat Tables
            $iptables -t nat -F
            $iptables -t nat -X
            $iptables -t nat -Z
        
        # Reset Mangle Tables
            $iptables -t mangle -F
            $iptables -t mangle -X
            $iptables -t mangle -X


echo "Deny all IPv4 traffic except where explicitly allowed"
        # Set The Default IPv4 Policy
            $iptables -P INPUT DROP
            $iptables -P FORWARD DROP
            $iptables -P OUTPUT DROP

echo "Deny all IPv6 traffic"
        # Drop all IPv6 packets
            $ip6tables -P INPUT DROP
            $ip6tables -P FORWARD DROP
            $ip6tables -P OUTPUT DROP

echo "Disable all attmpts to connect to mysql over the network"
        # Deny network access to sql server
            $iptables -A INPUT -p tcp --dport 3306 -j DROP
            $iptables -A OUTPUT -p tcp --sport 3306 -j DROP

echo "Configuring loopback interface"
        # Do not block loopback interface
            $iptables -A INPUT -i lo -j ACCEPT

	# Drop remote packets claiming to be from a loopback address.
            $iptables -A INPUT -s 127.0.0.0/8 ! -i lo -j DROP

        # Allow Established and Related Connections
            $iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
            $iptables -A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

        # Allow full outgoing connection but no incomming stuff
            #$iptables -A INPUT -i -m state --state ESTABLISHED,RELATED -j ACCEPT
	    #$iptables -A OUTPUT -o ens4 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT


echo "Applying ICMP Rules"

        # Chain for preventing ping flooding - up to 6 pings per second from a single
        # source, again with log limiting. Also prevents us from ICMP REPLY flooding
        # some victim when replying to ICMP ECHO from a spoofed source.
            $iptables -N ICMPFLOOD
            $iptables -A ICMPFLOOD -m recent --set --name ICMP --rsource
            $iptables -A ICMPFLOOD -m recent --update --seconds 1 --hitcount 6 --name ICMP --rsource --rttl -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix '** SUSPECT **'
            $iptables -A ICMPFLOOD -m recent --update --seconds 1 --hitcount 6 --name ICMP --rsource --rttl -j DROP
            $iptables -A ICMPFLOOD -j ACCEPT

        # Permit useful IMCP packet types for IPv4.
            $iptables -A INPUT -p icmp --icmp-type 0  -m conntrack --ctstate NEW -j ACCEPT
            $iptables -A INPUT -p icmp --icmp-type 3  -m conntrack --ctstate NEW -j ACCEPT
            $iptables -A INPUT -p icmp --icmp-type 11 -m conntrack --ctstate NEW -j ACCEPT

        # Permit IMCP ping requests and use ICMPFLOOD chain for preventing ping flooding.
            $iptables -A INPUT -p icmp --icmp-type 8  -m conntrack --ctstate NEW -j ICMPFLOOD

echo "Applying Rules To Drop and Reject Invalid, Banned, AUTH"
# Drop and Reject Specified Traffic
        # Drop Banned Traffic
            for i in ${THEBANNED}; do
              $iptables -A INPUT -s $i -j DROP
            done

        # Drop Invalid Packets
            $iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

        # Explicately reject AUTH traffic
            $iptables -A INPUT -p tcp --dport 113 --syn -m conntrack --ctstate NEW -j REJECT --reject-with tcp-reset

echo "Applying Rules to block all other bad stuff"
        # Block bad stuff
            $iptables -A INPUT -i $pub_int -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
            $iptables -A INPUT -i $pub_int -p tcp --tcp-flags ALL ALL -j DROP
            $iptables -A INPUT -i $pub_int -p tcp --tcp-flags ALL NONE -m limit --limit 5/m --limit-burst 7 -j LOG --log-prefix '** SUSPECT **'
            $iptables -A INPUT -i $pub_int -p tcp --tcp-flags ALL NONE -j DROP # NULL packets
            $iptables -A INPUT -i $pub_int -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
            $iptables -A INPUT -i $pub_int -p tcp --tcp-flags SYN,FIN SYN,FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-prefix '** SUSPECT **'
            $iptables -A INPUT -i $pub_int -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP #XMAS
            $iptables -A INPUT -i $pub_int -p tcp --tcp-flags FIN,ACK FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-prefix '** SUSPECT **'
            $iptables -A INPUT -i $pub_int -p tcp --tcp-flags FIN,ACK FIN -j DROP # FIN packet scans
            $iptables -A INPUT -i $pub_int -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

echo "Applying rules to define what traffic is permitted"
# Specify exactly what traffic is allowed

        # Allow DNS
            $iptables -A OUTPUT -p udp -o eth0 --dport 53 --sport 1024:65535 -j ACCEPT
            $iptables -A INPUT -p udp -i eth0 --sport 53 --dport 1024:65535 -j ACCEPT
            $iptables -A INPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
            $iptables -A OUTPUT -p udp --sport 53 -m state --state ESTABLISHED,RELATED -j ACCEPT
            $iptables -A INPUT -p tcp --destination-port 53 -m state --state NEW,ESTABLISHED,RELATED  -j ACCEPT
            $iptables -A OUTPUT -p tcp --sport 53 -m state --state ESTABLISHED,RELATED -j ACCEPT

        # Allow all HTTPS and HTTP traffic
            $iptables -A INPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
            $iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT

        # Allow Sending Email on Port 2525
            $iptables -A OUTPUT -p tcp --sport 2525 -m conntrack --ctstate ESTABLISHED -j ACCEPT
            $iptables -A INPUT -p tcp --dport 2525 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

        # Allow SSH connections port 22
            $iptables -A INPUT -i ens4 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
            $iptables -A OUTPUT -o ens4 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# Special Settings
echo "Limiting number of parallel connections to web server"
        # Limit Number of Parallel Connections to HTTP and HTTPS to 20 Per Client IP
            $iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 20 --connlimit-mask 24 -j DROP
            $iptables -A INPUT -p tcp --syn --dport 443 -m connlimit --connlimit-above 20 --connlimit-mask 24 -j DROP

exit 0
## END Script
