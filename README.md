# Python-Scapy-Packet-Sniffer
A quick packet Sniffer developed using python2 scapy to capture TCP, UDP and ICMP Packets in linux .This script is tested on linux Operating System on python version2. The script captures all the incoming and outgoing packets from all interface of the machine. Once the packets are captures they are classfies into TCP, UDP and ICMP packets based on their header.Under each classification the packets are categorized into incoming and outgoing packets.Some of the information captures by Packet Sniffer is Time Stamp, Source mac,Destination Mac,source IP Address, Destination IP Address, 
,Geo-Location. The dependent modules are Builtin [ os, datetime, socket, time,] and External [Geo-ip & Scapy] . Scapy and Geo-Ip are not pre-installed in linux.
and hence needs to be installed.

#Installing External Modules:  
sudo apt install scapy  
pip install python-geoip-geolite2    

# To download and Run Script
git clone https://github.com/Papu11/Python-Scapy-Packet-Sniffer.git
cd Python-Scapy-Packet-Sniffer/
sudo python python-packet-sniffer.py 
