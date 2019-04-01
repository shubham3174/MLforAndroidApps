# for usability
import argparse
import logging

# for verification
import os

# for packet parsing
import pyshark

# burst structure
class Burst():
	timestamp = None
	src_ip = None
	dst_ip = None
	src_port = None
	dst_port = None
	protocol = None
	num_packets_sent = 0
	num_packets_recv = 0
	num_bytes_sent = 0
	num_bytes_recv = 0

	def __init__(self, packets):
		self.src_ip = packets[0].src_ip
		self.dst_ip = packets[0].dst_ip
		self.src_port = packets[0].src_port
		self.dst_port = packets[0].dst_port
		self.protocol = packets[0].protocol
			
		self.num_packets_sent = 0
		self.num_packets_recv = 0
		self.num_bytes_sent = 0
		self.num_bytes_recv = 0

		# for packet in packets:
			# self.num_packets_sent += 1
			# self.num_bytes_sent += packet.num_bytes_sent	
			# 
	def print_burst(self):
		print("~~~ New Burst ~~~")
		print(self.timestamp)
		print(self.src_ip)
		print(self.dst_ip)
		print(self.src_port)
		print(self.dst_port)
		print(self.protocol)
		print(self.num_packets_sent)
		print(self.num_packets_recv)
		print(self.num_bytes_sent)
		print(self.num_bytes_recv)

class Flow():
	timestamp = None
	src_ip = None
	dst_ip = None
	src_port = None
	dst_port = None
	protocol = None
	num_packets_sent = 0
	num_bytes_sent = 0
	packets = None #list of all packets

	def __init__(self, packets):
		self.timestamp = packets[0].timestamp
		self.src_ip = packets[0].src_ip
		self.dst_ip = packets[0].dst_ip
		self.src_port = packets[0].src_port
		self.dst_port = packets[0].dst_port
		self.protocol = packets[0].protocol
		self.num_packets_sent = len(packets)
		self.num_bytes_sent = sum(packet.num_bytes_sent for packet in packets)
		self.packets = packets

	# def updateValues(self):

	def printFlow(self):
		# <timestamp> <srcaddr> <dstaddr> <srcport> <dstport> <proto>\<#packets sent> <#packets rcvd> <#bytes send> <#bytes rcvd>
		print(self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol, self.num_packets_sent, self.num_bytes_sent)
		
	def pretty_print(self):
		print("~~~ New Flow ~~~")
		print("Source IP: ", self.src_ip)
		print("Source Port: ", self.src_port)
		print("Destination IP: ", self.dst_ip)
		print("Destination Port: ", self.dst_port)
		print("Protocol: ", self.protocol)
		print("Timestamp: ", self.timestamp)
		print("Packets sent: ", self.packets_sent)
		print("Bytes sent: ", self.bytes)

# packet structure
class Packet():
	src_ip = None
	dst_ip = None
	src_port = None
	dst_port = None
	protocol = None
	timestamp = None
	num_packets_sent = None
	num_bytes_sent = 0
	
	def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol, timestamp):
		self.src_ip = src_ip
		self.src_port = src_port
		self.dst_ip = dst_ip
		self.dst_port = dst_port
		self.protocol = protocol
		self.timestamp = timestamp

	def pretty_print(self):
		print("~~~ New Packet ~~~")
		print("Source IP: ", self.src_ip)
		print("Source Port: ", self.src_port)
		print("Destination IP: ", self.dst_ip)
		print("Destination Port: ", self.dst_port)
		print("Protocol: ", self.protocol)
		print("Timestamp: ", self.timestamp)

def addPacket(packet, flows):
	newFlow = Flow([packet])
	flows.append(newFlow)
	return flows
	
# tries to make a Packet object from a packet
# if the packet is incomplete then it returns None
def parse_packet(packet):
	try:
		pkt = Packet(packet.ip.src, packet[packet.transport_layer].srcport, packet.ip.dst, packet[packet.transport_layer].dstport, packet.transport_layer, packet.sniff_timestamp)
		return pkt
	except AttributeError:
		return None

def parse_file(file):
	list_of_packets = []

	packets = pyshark.FileCapture(file)
	for packet in packets:
		parsed_packet = parse_packet(packet)
		if parsed_packed is not None:
			list_of_packets.append(parsed_packet)

	return list_of_packets

def parse_live():
	live_cap = pyshark.LiveCapture(interface="eth1")
	iterate = live_cap.sniff_continuously
	
	for packet in iterate():
		parsed_packet = parse_packet(packet)
		if parsed_packet is not None:
			parsed_packet.pretty_print()
			# TODO add burst stuff here

def main():
	parser = argparse.ArgumentParser(description="parse pcap files")
	parser.add_argument("-l", "--liveparse", action=store_true, help="live parse packets")
	parser.add_argument("-f", "--file", help="the file to parse")
	
	args = parser.parse_args()

	if args.liveparse:
		parse_live()
		exit()
	else:
		if not os.path.exists(args.file):
			logging.error("input a valid file to be parsed")
			exit()

		# list of flows to be maintained
		flows = []

		packets = parse_file(args.file)

		for packet in packets:
			flows = addPacket(packet, flows)

		for flow in flows:
			flow.printFlow()


if __name__ == "__main__":
	main()

