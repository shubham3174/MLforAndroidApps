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
from sklearn import linear_model
from sklearn import cluster
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

def export_data(file):
	first = 1
	
	with open(file) as csv_file:
		reader = csv.reader(csv_file, delimiter=',')
		for row in reader:
			if first: 
				features = np.array([row[6], row[9], row[7]])
				labels = np.array([row[8]])
				first = 0
			else:
				features = np.vstack((features, [row[6], row[9], row[7]]))
				labels = np.vstack((labels, [row[8]]))
	#print features
	#print labels			
	return features, labels
	
# *** COPIED FROM OTHER FILE tries to make a Packet object from a packet
# if the packet is incomplete then it returns None
def parse_packet(packet, appname):
	try:
		ppacket = Packet(packet.ip.src, packet[packet.transport_layer].srcport, packet.ip.dst, packet[packet.transport_layer].dstport, packet.transport_layer, packet.sniff_timestamp, int(packet.length), appname, packet.eth.type, packet.ip.ttl, packet.ip.flags, packet.ip.proto)
		return ppacket
	except AttributeError:
		return None
				
def train_model_tree(train, train_labels):
	model = DecisionTreeClassifier()
	fitted = model.fit(train, train_labels)
	return fitted 
	
def predict(model, test, test_labels):
	predicted = model.predict(test)
	score = model.score(test, test_labels)

	print 'Predicted: ', predicted
	print 'Mean Accuracy: ', score

	return predicted
	
def print_results(ppackets, predicted):
	new_predicted = []
	for n, i in enumerate(predicted):
		if i== 1:
			new_predicted.append("Wikipedia")
		elif i==2:
			new_predicted.append("Youtube")
		elif i==3:
			new_predicted.append("WeatherChannel")
		elif i==4:
			new_predicted.append("GoogleNews")
		elif i==5:
			new_predicted.append("FruitNinja")
	burst = Burst(ppackets[0])
	i = 0
	
	for ppacket in ppackets[1:]:
		if ppacket.timestamp >= burst.timestamp_lastrecvppacket + 1.0:
			for flow in burst.flows:
				flow.label = new_predicted[i]
				i += 1
			burst.pretty_print()
			burst.clean_me()
			burst = Burst(ppacket)
		else:
			burst.add_ppacket(ppacket)
	

def parse_file(file, appname):
	list_of_packets = []
	packets = pyshark.FileCapture(file)
	for packet in packets:
		ppacket = parse_packet(packet, appname)
		if ppacket is not None:
			list_of_packets.append(ppacket)

	return list_of_packets
	
def parse_live(model):
	first_ppacket = True
	
	csv_file = open("giventraffic.csv", "wb")
	writer = csv.writer(csv_file, delimiter=',')

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
					
					csv_file.close()
					test_features, test_labels = export_data("giventraffic.csv")
					predicted = predict(model, test_features, test_labels)
					print_results(burst.ppackets, predicted)
					
					csv_file = open("giventraffic.csv", "wb")
					writer = csv.writer(csv_file, delimiter=',')
					
					burst.clean_me()
					burst = Burst(ppacket)
				else:
					burst.write_to_csv(ppacket)
					
	
def main():
	parser = argparse.ArgumentParser(description="classify flows")
	parser.add_argument("-t", "--training", help="the training data, CSV")
	parser.add_argument("-e", "--testing", help="the testing data, PCAP")
	parser.add_argument("-l", "--live", action="store_true", help="Live parse data as testing data")
	
	args = parser.parse_args()

	train_features, train_labels = export_data(args.training)
	for n, i in enumerate(train_labels):
		if i=="Wikipedia":
			train_labels[n] = 1
		elif i=="Youtube":
			train_labels[n] = 2
		elif i=="WeatherChannel":
			train_labels[n] = 3
		elif i=="GoogleNews":
			train_labels[n] = 4
		elif i=="FruitNinja":
			train_labels[n] = 5
	if args.live:
		parse_live()
	else:  

		gen = 0
		if os.path.dirname(args.testing).replace("Samples/", "").replace("/", "") in ["Wikipedia", "Youtube", "WeatherChannel", "GoogleNews", "FruitNinja"]:
			gen_label = os.path.dirname(args.testing).replace("/", "").replace("Samples","")
			if gen_label=="Wikipedia":
				gen = 1
			elif gen_label == "Youtube":
				gen = 2
			elif gen_label == "WeatherChannel":
				gen = 3
			elif gen_label == "GoogleNews":
				gen = 4
			elif gen_label == "FruitNinja":
				gen = 5
			else:
				gen = 0

		ppackets = parse_file(args.testing, gen)

		burst = Burst(ppackets[0])

		csv_file = open("giventraffic.csv", "wb")
		writer = csv.writer(csv_file, delimiter=',')
		
		for ppacket in ppackets[1:]:
			if ppacket.timestamp >= burst.timestamp_lastrecvppacket + 1.0:
				#burst.pretty_print()
				burst.write_to_csv(writer)
				burst.clean_me()
				burst = Burst(ppacket)
			else:
				burst.add_ppacket(ppacket)
				
		csv_file.close()
	
		test_features, test_labels = export_data("giventraffic.csv")

		model = train_model_tree(train_features.astype("float"), train_labels.astype("float"))
		predicted = predict(model, test_features.astype("float"), test_labels.astype("float"))

		print_results(ppackets, predicted)
	

if __name__ == "__main__":
	main()

