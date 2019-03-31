# for usability
import argparse
import logging

# for verification
import os

# for packet parsing
import dpkt

def parse_packet(packet):
	return 0

def parse_file(file):
	for ts, pkt in dpkt.pcap.Reader(open(file, 'r')):
		print ts, pkt

	return 0

def main():
	parser = argparse.ArgumentParser(description="parse pcap files")
	parser.add_argument("-f", "--file", required=True, help="the file to parse")
	
	args = parser.parse_args()

	if not os.file.exists(args.file):
		logging.error("input a valid file to be parsed")
		exit()

#	parse_file(args.file)
	

	f = open(args.file, "r")
	lines = f.readlines()
	for line in lines:
		print line
	f.close()


if __name__ == "__main__":
	main()
