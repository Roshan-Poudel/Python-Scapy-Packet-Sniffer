#!/usr/bin/python

from scapy.all import *
import socket
import datetime
import os
import time

def network_monitoring_for_visualization_version(pkt):
	time=datetime.datetime.now()
		#classifying packets into TCP
	if pkt.haslayer(TCP):
		# classyfying packets into TCP Incoming packets
		if socket.gethostbyname(socket.gethostname())== pkt[IP].dst:
			print(str("[")+str(time)+str("]")+"  "+"TCP-IN:{}".format(len(pkt[TCP]))+" Bytes"+"    "+"SRC-MAC:" +str(pkt.src)+"    "+ "DST-MAC:"+str(pkt.dst)+"    "+ "SRC-PORT:"+str(pkt.sport)+"    "+"DST-PORT:"+str(pkt.dport)+"    "+"SRC-IP:"+str(pkt[IP].src  )+"    "+"DST-IP:"+str(pkt[IP].dst  ))
	
		if socket.gethostbyname(socket.gethostname())==pkt[IP].src:
			print(str("[")+str(time)+str("]")+"  "+"TCP-OUT:{}".format(len(pkt[TCP]))+" Bytes"+"    "+"SRC-MAC:" +str(pkt.src)+"    "+ "DST-MAC:"+str(pkt.dst)+"    "+ "SRC-PORT:"+str(pkt.sport)+"    "+"DST-PORT:"+str(pkt.dport)+"    "+"SRC-IP:"+str(pkt[IP].src)+"    "+"DST-IP:"+str(pkt[IP].dst))
	#classifying packets into UDP	
	if pkt.haslayer(UDP):
		if socket.gethostbyname(socket.gethostname())==pkt[IP].src:
			# classyfying packets into UDP Outgoing packets
			print(str("[")+str(time)+str("]")+"  "+"UDP-OUT:{}".format(len(pkt[UDP]))+" Bytes "+"    "+"SRC-MAC:" +str(pkt.src)+"    "+"DST-MAC:"+ str(pkt.dst)+"    "+"SRC-PORT:"+ str(pkt.sport) +"    "+"DST-PORT:"+ str(pkt.dport)+"    "+"SRC-IP:"+ str(pkt[IP].src)+"    "+"DST-IP:"+ str(pkt[IP].dst))
	   
		if socket.gethostbyname(socket.gethostname())==pkt[IP].dst:
			# classyfying packets into UDP Incoming packets
			print(str("[")+str(time)+str("]")+"  "+"UDP-IN:{}".format(len(pkt[UDP]))+" Bytes "+"    "+"SRC-MAC:" +str(pkt.src)+"    "+"DST-MAC:"+ str(pkt.dst)+"    "+"SRC-PORT:"+ str(pkt.sport) +"    "+"DST-PORT:"+ str(pkt.dport)+"    "+"SRC-IP:"+ str(pkt[IP].src)+"    "+"DST-IP:"+ str(pkt[IP].dst))
		#classifying packets into ICMP
	if pkt.haslayer(ICMP):
		# classyfying packets into UDP Incoming packets
		if socket.gethostbyname(socket.gethostname())==pkt[IP].src:
			print(str("[")+str(time)+str("]")+"  "+"ICMP-OUT:{}".format(len(pkt[ICMP]))+" Bytes"+"    "+"IP-Version:"+str(pkt[IP].version) +"    "*1+" SRC-MAC:"+str(pkt.src)+"    "+"DST-MAC:"+str(pkt.dst)+"    "+"SRC-IP: "+str(pkt[IP].src)+ "    "+"DST-IP:  "+str(pkt[IP].dst))	
							 
		if socket.gethostbyname(socket.gethostname())==pkt[IP].dst:
			print(str("[")+str(time)+str("]")+"  "+"ICMP-IN:{}".format(len(pkt[ICMP]))+" Bytes"+"    "+"IP-Version:"+str(pkt[IP].version)+"    "*1+"	 SRC-MAC:"+str(pkt.src)+"    "+"DST-MAC:"+str(pkt.dst)+"    "+"SRC-IP: "+str(pkt[IP].src)+ "    "+"DST-IP:  "+str(pkt[IP].dst))	
if __name__ == '__main__':
	sniff(prn=network_monitoring_for_visualization_version)
