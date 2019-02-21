# coding : utf8 
import socket
import binascii
import struct

def ipToBytes(str):
	output = b''
	ip_array = str.split('.')
	for ch in ip_array:
		output += (int(ch).to_bytes(1,byteorder='big'))
	print (output)
	senderIpAdr = socket.inet_aton("192.168.1.25")
	print(senderIpAdr)
	return output
	
def macToBytes(str):
	output = b''
	mac_array = str.split(':')
	for ch in mac_array:
		output += bytes(0) + (int(ch,16).to_bytes(1,byteorder='big'))
	print (output)
	print( binascii.unhexlify(str.replace(':','')))
	return output

def mactobinar(mac): 
	return binascii.unhexlify(mac.replace(':',''))

def buildArpHeaderManually(ipdst,hwdst,ipsrc):
	htype =1 # HardwareType
	ptype = 0x0800 # Protocol type IPV4 
	hsize = 6 # Hardware adresse len
	psize = 4 # Protocol adress len
	opcode = 2 # 1 = request , 2 = response 
	senderMacAdr ='xx:xx:xx:xx:xx'
	
	output = (bytes(1) + int(htype).to_bytes(1,byteorder='big') + ptype.to_bytes(2,byteorder='big'))
	output += (int(hsize).to_bytes(1,byteorder='big') + int(psize).to_bytes(1,byteorder='big') + int(opcode).to_bytes(2,byteorder='big') )
	output += macToBytes(senderMacAdr) + ipToBytes(ipsrc) + macToBytes(hwdst) + ipToBytes(ipdst)

	print (output)


def buildArpHeader(ipdst,hwdst,ipsrc):
	htype =1 # HardwareType
	ptype = 0x0800 # Protocol type IPV4 
	hsize = 6 # Hardware adresse len
	psize = 4 # Protocol adress len
	opcode = 2 # 1 = request , 2 = response 
	senderMacAdr = mactobinar('xx:xx:xx:xx:xx')
	senderIpAdr = socket.inet_aton(ipsrc)
	targetMacAdr = mactobinar(hwdst)
	targetIpAdr = socket.inet_aton(ipdst)
	arp_hdr = struct.pack("!HHBBH6s4s6s4s",htype,ptype,hsize,psize,opcode,senderMacAdr,senderIpAdr,targetMacAdr,targetIpAdr)
	print(arp_hdr)


ipToBytes('192.168.1.25')
macToBytes("00:c0:ca:97:9a:0c")
buildArpHeader('192.168.1.25','xx:xx:xx:xx:xx','192.168.1.10')
buildArpHeaderManually('192.168.1.25','xx:xx:xx:xx:xx','192.168.1.10')

