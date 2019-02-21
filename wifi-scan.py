import socket 


def snif():
	rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
	rawSocket.bind(("wlan1mon", 0x0003))
	ap_list = set()
	while True :
		pkt = rawSocket.recvfrom(3200)[0]
		if hex(pkt[36]) == "0x80" :
			pos_ssid_start = 74
			pos_ssid_end = 74 + int(pkt[73])
			pos_mac_start = 52
			pos_mac_end = 58
			mac_adr =''
			for i in range(52,58):
				mac_adr += hex(pkt[i])
				if i < 57 :
					mac_adr += ':'
			mac_adr = mac_adr.replace('0x','')
			channel = pkt[98]
			print("SSID : %s, Mac : %s,  Channel %s" % (pkt[pos_ssid_start:pos_ssid_end].decode('utf-8'),mac_adr,channel))

snif()
