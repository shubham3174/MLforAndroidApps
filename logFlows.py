# for usability
import argparse
import logging

# for verification
import os

# for packet parsing
import pyshark

# burst structure
class Burst():
	src_ip = None
	dst_ip = None
	src_port = None
	dst_port = None
	protocol = None
	num_packets_sent = None	
	num_packets_recv = None
	num_bytes_sent = None
	num_bytes_recv = None

	def __init__(self, packets):
		self.src_ip = packets[0].src_ip
		self.dst_ip = packets[0].dst_ip
		self.src_port = packets[0].src_port
		self.dst_port = packets[0].dst_port
		self.protocol = packets[0].protocol
			
		self.num_packets_sent = 0
		self.num_packets_recv = 0
		self.num_bytes_sent = None
		self.num_bytes_recv = None

		for packet in packets:
			self.num_packets_sent += 1
			self.num_bytes_sent += packet.num_bytes_sent			



# packet structure
class Packet():
	src_ip = None
	dst_ip = None
	src_port = None
	dst_port = None
	protocol = None
	num_packets_sent = None
	num_bytes_sent = None
	
	def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol):
		self.src_ip = src_ip
		self.src_port = src_port
		self.dst_ip = dst_ip
		self.dst_port = dst_port
		self.protocol = protocol

	def pretty_print(self):
		print("Source IP: ", self.src_ip)
		print("Source Port: ", self.src_port)
		print("Destination IP: ", self.dst_ip)
		print("Destination Port: ", self.dst_port)
		print("Protocol: ", self.protocol)

def parse_packet(packet):
	if 'ip' not in str(dir(packet)):
		print(packet.pretty_print())
		import pdb; pdb.set_trace()
	pkt = Packet(packet.ip.src, packet[packet.transport_layer].srcport, packet.ip.dst, packet[packet.transport_layer].dstport, packet.transport_layer)
	return pkt

def parse_file(file):
	list_of_packets = []

	packets = pyshark.FileCapture(file)
	for packet in packets:
		parsed_packet = parse_packet(packet)
		parsed_packet.pretty_print()
		list_of_packets.append(parsed_packet)

	return list_of_packets

def main():
	parser = argparse.ArgumentParser(description="parse pcap files")
	parser.add_argument("-f", "--file", required=True, help="the file to parse")
	
	args = parser.parse_args()

	if not os.path.exists(args.file):
		logging.error("input a valid file to be parsed")
		exit()

	parse_file(args.file)


if __name__ == "__main__":
	main()

