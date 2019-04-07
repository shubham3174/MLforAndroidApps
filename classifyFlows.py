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

# for machine learning
from sklearn.svm import SVC
import numpy as np

def export_data(file):
	first = 1
	
	with open(file) as csv_file:
		reader = csv.reader(csv_file, delimiter=',')
		for row in reader:
			if first: 
				features = np.array([row[9], row[7]])
				labels = np.array([row[8]])
				first = 0
			else:
				features = np.vstack((features, [row[9], row[7]]))
				labels = np.vstack((labels, [row[8]]))
	print features
	print labels			
	return features, labels
	
# *** COPIED FROM OTHER FILE tries to make a Packet object from a packet
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

def train_model_SVM(train, train_labels, test, test_labels):
	model = SVC(kernel='linear')
	fitted = model.fit(train, train_labels)
	predicted = fitted.predict(test)
	score = fitted.score(test, test_labels)
	
	return score
				
				
def main():
	parser = argparse.ArgumentParser(description="classify flows")
	parser.add_argument("-t", "--training", help="the training data")
	parser.add_argument("-e", "--testing", help="the testing data")
	
	args = parser.parse_args()

	train_features, train_labels = export_data(args.training)
	ppackets = parse_file(args.testing)

	burst = Burst(ppackets[0])

	csv_file = open("giventraffic.csv", "wb")
	writer = csv.writer(csv_file, delimiter=',')
	for ppacket in ppackets[1:]:
		if ppacket.timestamp >= burst.timestamp_lastrecvppacket + 1.0:
			burst.pretty_print()
			burst.write_to_csv(writer)
			burst.clean_me()
			burst = copy.deepcopy([])
			burst = Burst(ppacket)
		else:
			burst.add_ppacket(ppacket)
			
	csv_file.close()
	
	test_features, test_labels = export_data("giventraffic.csv")
	
	# classify 
	score = train_model_SVM(train_features, train_labels, test_features, test_labels)	


if __name__ == "__main__":
	main()

