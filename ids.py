#!/usr/bin/python
# === A custom intrusion detection system used to monitor traffic for known
# === attacks based on provided signaures.

import sys
import math

# === Defined IPs ===
waterlooIP = "23.91.163.0/24"
kitchenerIP = "23.91.184.0/23"

# === Boolean for handshake acknowledged
acknowledged = False

# === Function used to later determine if IPs are within another IP's range
# Given an IP in the form of CIDR find the number of IP fields to check 
# as well as a mask used to determine if a given field is in range of an IP
# address. 
#	Parameters: string -- ip address 
#	Output: 	tuple -- # of fields to check in an ip prefix, mask # used to '&'' with 
#				IP field to check based on prefix size
def checkIP(ip):
	data = ip.split("/")
	prefixSize = data[1]
	fieldsToCheck = math.ceil(int(prefixSize)/8)
	mask = ~ ((1 << (8 - (int(prefixSize) % 8))) - 1)

	return (int(fieldsToCheck), mask)

# === Check if provided IP is within LAN ===
# IP address must be of the form 10.97.*.* where * is a value from 
# 0 to 255.
#	Parameters:	list of ints -- contents of an ip address
# 	Output:		boolean
def localIP(ipContents):
	if (ipContents[0] == 10 and ipContents[1] == 97):
		return True
	else:
		return False


# === Check if a provided IP address is within KW IP range ===
#	Parameters:	list of ints -- contents of an ip address
#	Output:		boolean
def kwIP(ipContents):
	kData = kitchenerIP.split("/")
	kIP = map(lambda x: int(x), kData[0].split("."))

	# Grab the number of fields to check in IP prefix and the mask used to check 
	# if 'the field to check' is in range
	fields, mask = checkIP(kitchenerIP)

	# Field that needs to be checked in given IP. This is if the prefix size is not a multiple of 
	# 8 and this can result in a range of numbers.
	ipContents[fields - 1] = ipContents[fields - 1] & mask

	# Check prefix fields that won't have a range
	for i in range(fields):
		if ipContents[i] != kIP[i]:
			return False

	return True

# === Check if remote computer tries to connect with LAN server
#	Parameters:	source IP, destination IP
#	Output:		boolean
def tryToConnect(srcIPContents, destIPContents):
	if (not localIP(srcIPContents) or not kwIP(srcIPContents)) and \
			(localIP(destIPContents) or kwIP(destIPContents)):
		return True
	else: 
		return False

# === Read in log file of packets
while True:
	# Read in from standard input
	line = sys.stdin.readline()

	# Check for end of the log file
	if not line:
		break
	
	# Check if at the beginning of a new packet
	if line[2] is ":":

		# Read the next line to check src/dest IP addresses
		ipHeader = sys.stdin.readline().strip()
		ipHeader = ipHeader.split(":")

		# Split the ipHeader into src/dst IPs and IP fields
		ips = ipHeader[0].split(" > ")
		fields = ipHeader[1].strip().split(", ")

		srcIP = ips[0]
		destIP = ips[1]

		srcIPContents = map(lambda x: int(x), srcIP.split("."))
		destIPContents = map(lambda x: int(x), destIP.split("."))

		seq = fields[2].split()[0]
		seqValue = fields[2].split()[1]

		# If there is an initial attempt to connect during handshake, ack will not appear as a field
		if fields[3].split()[0] == "ack":
			acknowledged = True
			ackValue = fields[3].split()[1]

		# === SPOOF ATTACK ===
		# Recall: at least one of the source and destination addresses should be in the 10.97.0.0/16 IP range.
		# So if they're BOTH not in the range, then there is a spoof attack
		if not localIP(srcIPContents) and not localIP(destIPContents):
			print "[Spoofed IP address]: " + "src:" + srcIP + ", dst:" + destIP

		# === UNAUTHORIZED ACCESS ===
		# Attempted Connection
		if tryToConnect(srcIPContents, destIPContents) and \
				(seq == "seq" and seqValue > 1) and not acknowledged:
			print "[Attempted server connection]: " + "rem:" + srcIP + ", srv:" + destIP

		# Accepted Connection
		if tryToConnect(srcIPContents, destIPContents) and \
				(seqValue == "1" and ackValue == "1"):
			print "[Accepted server connection]: " + "rem:" + srcIP + ", srv:" + destIP

