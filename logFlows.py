# for usability
import argparse
import logging

# for verification
import os

# for packet parsing
import pyshark

# packet structure
class Packet():
	src_ip = None
	dst_ip = None
	src_port = None
	dst_port = None
	protocol = None
	num_packets_sent = None
	num_packets_recv = None
	num_bytes_sent = None
	num_bytes_recv = None
	
	def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol):
		self.src_ip = src_ip
		self.src_port = src_port
		self.dst_ip = dst_ip
		self.dst_port = dst_port
		self.protocol = protocol

	def print(self):
		print "Source IP: ", self.src_ip
		print "Source Port: ", self.src_port
		print "Destination IP: ", self.dst_ip
		print "Destination Port: ", self.dst_port
		print "Protocol: ", self.protocol

def parse_packet(packet):
	pkt = Packet(packet.src, packet.dst, None, None, None)
	return pkt

def parse_file(file):
	packets = pyshark.FileCapture(file)
	for packet in packets:
		parse_packet(packet)
		return 0

	return 0

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

