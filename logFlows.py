# classes
from classes import Burst, Flow, Packet

# for usability
import argparse
import logging

# for verification
import os

# for python memory problems
import copy

# for logging
import csv

# for packet parsing
import pyshark
import datetime
import time
	
	
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

def parse_live(writer):
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
					burst.write_to_csv(writer)

					burst.clean_me()
					burst = Burst(ppacket)
				else:
					burst.write_to_csv(ppacket)
def main():
	parser = argparse.ArgumentParser(description="parse pcap files")
	parser.add_argument("-l", "--liveparse", action="store_true", help="live parse packets")
	parser.add_argument("-f", "--file", help="the file to parse")
	
	args = parser.parse_args()
	
	csv_file = open("traffic.csv", "wb")
	writer = csv.writer(csv_file, delimiter=',')
	
	# rows in csv file are
	#     type: 'packet' or 'flow'
	#     protocol: 'udp', 'tcp', etc.
	# writer.writerow(["type", "protocol", "label"])
	

	if args.liveparse:
		parse_live(writer)
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
				burst.write_to_csv(writer)
				burst.clean_me()
#				del burst.flows
				burst = copy.deepcopy([])
				burst = Burst(ppacket)
			else:
				burst.add_ppacket(ppacket)
				
		csv_file.close()

if __name__ == "__main__":
	main()

