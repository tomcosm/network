# coding: utf8

import socket
import sys
import os 
import time
from threading import Thread
import glob
import json


class DnsServer(Thread):

	def __init__(self):
		Thread.__init__(self)
		self.port = 53
		self.ip = "192.168.1.25"
		self.kill_received = False
		self.zonedata = self.load_zone()

	# get ./zones files content
	def load_zone(self):
		json_zone = {}
		zonefiles = glob.glob('zones/*.zone')
		for zone in zonefiles : 
			with open(zone) as zonedata: 
				data = json.load(zonedata)
				zone_name = data["$origin"] 
				json_zone[zone_name] = data
		return json_zone


	# Construct the hexadecimal Response Flags
	def get_flags(self,flags):
		rflags = ''
		QR = '1'  # set to 1 to Response
		byte1 = bytes(flags[:1])
		byte2 = bytes(flags[1:2])
		# ??? 
		OPCODE =''
		for bit in range(1,5):
			OPCODE += str(ord(byte1)&(1<<bit))
		AA = '1' ### ??? 
		TC = '0' # Truncate message
		RD = '0' # Recursion
		RA = '0' # ???
		Z= '000' # Reserved
		RCODE = '0000'
		rflags = int(QR+OPCODE+AA+TC+RD,2).to_bytes(1, byteorder="big")+int(RA+Z+RCODE,2).to_bytes(1,byteorder='big')
		return rflags

	# extract the domain and the Query Type form the query
	# return a tuple , domaineapert as Array and Query Type as byte
	def get_question_domain(self,data):
		state = 0 
		expectedlength= 0
		domainString =''
		domainpart=[]
		x = 0
		y = 0
		for byte in data:
			if state == 1: 
				if byte != 0 :
					domainString += chr(byte) ## every bytes (octets) = domain name letter
				x += 1
				if x == expectedlength:
					domainpart.append(domainString)
					domainString= ''
					state = 0
					x = 0
				if byte == 0 : 
					domainpart.append(domainString) ## tuto correction ?
					break
			else:
				state =1
				expectedlength = byte
			y += 1
		questionType = data[y:y+2] # tuto correction decalage not y+1:y+3
		return (domainpart, questionType)	

		# return the .zone record matching with the domain
	def get_zone(self,domain):
		zone_name = '.'.join(domain[:2])
		return self.zonedata[zone_name]

	# get the records dns from files matching qith the domain name
	def get_recs(self,data):
		domain, questionType = self.get_question_domain(data)
		qt = ''
		if questionType == b'\x00\x01': 
			qt = 'a'
		zone = self.get_zone(domain)
		return (zone[qt], qt ,domain)


	# convert the strings into bytes
	def build_question(self,domain_name,rectype):
		qbytes = b''
		#print (domain_name)
		#domain_name.append('')
		for part in domain_name:
			length = len(part)
			qbytes += bytes([length])
			for char in part : 
				qbytes += ord(char).to_bytes(1,byteorder='big')
		if rectype =='a':
			qbytes += (1).to_bytes(2,byteorder='big')

		qbytes += (1).to_bytes(2,byteorder='big')
		
		return qbytes


	# build the response into bytes
	def recToBytes(self,domain_name, rectype, recttl, recval):
		rbytes = b'\xc0\x0c'
		if rectype == 'a':
			rbytes = rbytes + bytes([0]) + bytes([1])

		rbytes = rbytes + bytes([0]) + bytes([1])
		rbytes += int(recttl).to_bytes(4,byteorder='big')
		if rectype =='a':
			rbytes = rbytes + bytes([0]) + bytes([4])
			for part in recval.split('.'):
				rbytes += bytes([int(part)])
		return rbytes


	def build_response(self,data):
		# Transaction id : on 2 first octets
		transactionId = data[:2]
		# byte is the interger format hex (0-255)
		TID = ''
		for byte in transactionId :
			try:
				TID += hex(byte)[2:] # reconvert to hexadecimal and only keep the 2 lasts chars
			except TypeError:
				pass
		# Flags on 2 octets
		flags = self.get_flags(data[2:4])	
		# Question count
		QDCOUNT = b'\x00\x01'
		# Answer count data[:12] is the queries 
		ANSCOUNT = len(self.get_recs(data[12:])[0]).to_bytes(2, byteorder ='big')
		# nameServer Count
		NSCOUNT = (0).to_bytes(2,byteorder ='big')
		# Additionnal count
		ARCOUNT = (0).to_bytes(2,byteorder ='big')

		dnsHeader= transactionId + flags + QDCOUNT + ANSCOUNT + NSCOUNT + ARCOUNT
		
		# Create DNS Body
		dnsBody = b''
		# Get answer
		records, rectype, domain_name= self.get_recs(data[12:])
		dnsQuestion = self.build_question(domain_name, rectype)
		for record in records:
			dnsBody += self.recToBytes(domain_name, rectype, record["ttl"], record["value"])
		return dnsHeader + dnsQuestion + dnsBody

	def run(self):
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.bind((self.ip,self.port))
		while not self.kill_received : 
			data, addr = sock.recvfrom(512)
			r = self.build_response(data)
			sock.sendto(r,addr)


try:
	test = DnsServer()
	test.start()
	while True: 
		time.sleep(0.5)
except KeyboardInterrupt : 
	test.kill_received = True
	test.join()
	print ("Bye bye ....")
	sys.exit(0)
