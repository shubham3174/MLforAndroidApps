# rows in csv file are
# *** FEATURE FOR CLASSIFIER
#     1: timestamp
#     2: srcaddr
#     3: dstaddr
#     4: srcport
#     5: dstport
# *** 6: protocol: 'udp', 'tcp', etc. 
#     7: #packets sent
# *** 8: #bytes sent
#     9: label
# *** 10: type: 'packet' or 'flow'
#     11: 
#     
	
	
# burst structure
class Burst():
	timestamp_lastrecvppacket = 0.0
	flows = []

	def __init__(self, firstppacket):
		self.add_ppacket(firstppacket)
		self.timestamp_lastrecvppacket = firstppacket.timestamp
		self.flows = []	
	
	def add_ppacket(self, ppacket):
		self.timestamp_lastrecvppacket = ppacket.timestamp
		for flow in self.flows:
			if flow.src_ip == ppacket.src_ip and flow.dst_ip == ppacket.dst_ip and flow.src_port == ppacket.src_port and flow.dst_port == ppacket.dst_port and flow.protocol == ppacket.protocol:
				flow.add_ppacket(ppacket)
				return
		newFlow = Flow(ppacket)
		self.flows.append(newFlow)


	def clean_me(self):
		self.timestamp_lastrecvppacket = 0.0
		for flow in self.flows:
			flow.clean_me()
			self.flows.remove(flow)
#		del flow.packets
#		print flow.packets
		self.flows = []	

	def pretty_print(self):
		print("~~~ New Burst ~~~")
		for flow in self.flows:
			# flow.pretty_print()
			flow.one_line_print()
			
	def write_to_csv(self, writer):
		for flow in self.flows:
			flow.write_to_csv(writer)

class Flow():
	timestamp = None
	src_ip = None
	dst_ip = None
	src_port = None
	dst_port = None
	protocol = None
	num_packets_sent = 0
	num_bytes_sent = 0
	packets = []
	length = 0

	def __init__(self, ppacket):
		self.timestamp = ppacket.timestamp
		self.src_ip = ppacket.src_ip
		self.dst_ip = ppacket.dst_ip
		self.src_port = ppacket.src_port
		self.dst_port = ppacket.dst_port
		self.protocol = ppacket.protocol
#		print 'test', self.packets
		self.packets = []
		self.add_ppacket(ppacket)

	def add_ppacket(self, ppacket):
		self.packets.append(ppacket)
		self.num_packets_sent += 1
		self.num_bytes_sent += ppacket.num_bytes

	def clean_me(self):
#		print self.packets
		for packet in self.packets:
			self.packets.remove(packet)		

		self.packets = []
#		print self.packets	
		
	def pretty_print(self):
		print("~~~ New Flow ~~~")
		print("Source IP: {}".format(self.src_ip))
		print("Source Port: {}".format(self.src_port))
		print("Destination IP: {}".format(self.dst_ip))
		print("Destination Port: {}".format(self.dst_port))
		print("Protocol: {}".format(self.protocol))
		print("Timestamp: {}".format(self.timestamp))
		print("Packets sent: {}".format(self.num_packets_sent))
		print("Bytes sent: {}".format(self.num_bytes_sent))

	def one_line_print(self):
#		print self.packets
		print("{} {} {} {} {} {} {} {}".format(self.timestamp, self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol, self.num_packets_sent, self.num_bytes_sent))
#		for packet in self.packets:
#			packet.one_line_print()
		
	def write_to_csv(self, writer):
		# write the packets to the csv (just in case)
		for packet in self.packets:
			packet.write_to_csv(writer)
			
		# write the flow to the csv
		writer.writerow(['flow', self.protocol])
		
# packet structure
class Packet():
	src_ip = None
	dst_ip = None
	src_port = None
	dst_port = None
	protocol = None
	timestamp = None
	num_bytes = 0
	
	def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol, timestamp, num_bytes):
		#TODO: Make __init__ populate number of bytes
		self.src_ip = src_ip
		self.src_port = src_port
		self.dst_ip = dst_ip
		self.dst_port = dst_port
		self.protocol = protocol
		self.timestamp = float(timestamp)
		self.num_bytes = num_bytes

	def pretty_print(self):
		print("~~~ New Packet ~~~")
		print("Source IP: ", self.src_ip)
		print("Source Port: ", self.src_port)
		print("Destination IP: ", self.dst_ip)
		print("Destination Port: ", self.dst_port)
		print("Protocol: ", self.protocol)
		print("Timestamp: ", self.timestamp)

	def one_line_print(self):
		print("\t{} {} {} {} {} {}".format(self.timestamp, self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))
		
	def write_to_csv(self, writer):
		writer.writerow(['packet', self.protocol])