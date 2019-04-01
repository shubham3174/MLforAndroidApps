# for usability
import argparse
import logging

# for verification
import os

# for python memory problems
import copy


# for packet parsing
import pyshark
import datetime
import time

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
		del flow.packets
#		print flow.packets
		self.flows = []	

	def pretty_print(self):
		print("~~~ New Burst ~~~")
		for flow in self.flows:
			# flow.pretty_print()
			flow.one_line_print()

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
		for packet in self.packets:
			packet.one_line_print()
		
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
	
	
# tries to make a Packet object from a packet
# if the packet is incomplete then it returns None
def parse_packet(packet):
	try:
		ppacket = Packet(packet.ip.src, packet[packet.transport_layer].srcport, packet.ip.dst, packet[packet.transport_layer].dstport, packet.transport_layer, packet.sniff_timestamp, int(packet.length))
		return ppacket
	except AttributeError:
		return None

def parse_file(file):
	list_of_packets = []
	packets = pyshark.FileCapture(file)
	for packet in packets:
		ppacket = parse_packet(packet)
		if ppacket is not None:
			list_of_packets.append(ppacket)

	return list_of_packets

def parse_live():
	first_ppacket = True

	live_cap = pyshark.LiveCapture(interface="eth1")
	iterate = live_cap.sniff_continuously
	
	for packet in iterate():
		ppacket = parse_packet(packet)
		if ppacket is not None:
			if first_ppacket == True:
				burst = Burst(ppacket)
				first_ppacket = False
			else:
				if ppacket.timestamp >= burst.timestamp_lastrecvppacket + 1.0:
					burst.pretty_print()

					burst.clean_me()
					burst = Burst(ppacket)
				else:
					burst.add_ppacket(ppacket)
def main():
	parser = argparse.ArgumentParser(description="parse pcap files")
	parser.add_argument("-l", "--liveparse", action="store_true", help="live parse packets")
	parser.add_argument("-f", "--file", help="the file to parse")
	
	args = parser.parse_args()

	if args.liveparse:
		parse_live()
	else:
		if not os.path.exists(args.file):
			logging.error("input a valid file to be parsed")
			exit()

		ppackets = parse_file(args.file)
		
		burst = Burst(ppackets[0])
		
		for ppacket in ppackets[1:]:
#			print ppacket.timestamp
			if ppacket.timestamp >= burst.timestamp_lastrecvppacket + 1.0:
				burst.pretty_print()
				burst.clean_me()
				del burst.flows
				burst = copy.deepcopy([])
				burst = Burst(ppacket)
			else:
				burst.add_ppacket(ppacket)

if __name__ == "__main__":
	main()

