# for usability
import argparse
import logging

# for verification
import os

# for packet parsing
import pyshark

def parse_packet(packet):
	print packet.info

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

