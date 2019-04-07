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
import datetime
import time

# for machine learning


def parse_file(file):
	first = 1
	
	with open(file) as csv_file:
		reader = csv.reader(csv_file, delimiter=',')
		for row in reader:
			if first: 
				features = np.array([row[0], row[1]])
				labels = np.array([row[2]])
				first = 0
			else:
				features = np.vstack(features, [row[0], row[1]])
				labels = np.vstack(labels, [row[2]])
				
	return features, labels
	

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

	train_features, train_labels = parse_file(args.training)
	test_features, test_labels = parse_file(args.testing)
	
	# classify 
	score = train_model_SVM(train_features, train_labels, test_features, test_labels)	


if __name__ == "__main__":
	main()

