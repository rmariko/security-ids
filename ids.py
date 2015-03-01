#!/usr/bin/python
# === A custom intrusion detection system used to monitor traffic for known
# === attacks based on provided signaures.

import sys
import math

# === List of Valid IPs ===
waterlooIP = "23.91.163.0/24"
kitchenerIP = "23.91.184.0/23"
localIP = "10.97.0.0/16"

ip_list = [waterlooIP, kitchenerIP, localIP]

# === Boolean for handshake acknowledged ===
acknowledged = False

# === List of malicious hosts ===
malicious_hosts = []

# === Function used to later determine if IPs are within another IP's range
# Given an IP in the form of CIDR find the number of IP fields to check 
# as well as a mask used to determine if a given field is in range of an IP
# address. 
#	Parameters: string -- ip address 
#	Output: 	tuple -- # of fields to check in an ip prefix, mask # used to '&'' with 
#				IP field to check based on prefix size
def getIPMaskField(ip):
	data = ip.split("/")
	prefixSize = data[1]
	fieldsToCheck = math.ceil(int(prefixSize)/8)

	mask = 255 if ((int(prefixSize) % 8) == 0) else (~ ((1 << (8 - (int(prefixSize) % 8))) - 1))

	return (int(fieldsToCheck), mask)

# === Check if a provided IP address is within KW IP range ===
#	Parameters:	list of ints -- contents of an ip address
#	Output:		boolean
def inRange(ipContents, validIPs):
	valid = True

	for validIP in validIPs:
		data = validIP.split("/")
		IP = map(lambda x: int(x), data[0].split("."))

		# Grab the number of fields to check in IP prefix and the mask used to check 
		# if 'the field to check' is in range
		fields, mask = getIPMaskField(validIP)

		original_field = ipContents[fields-1]
		# Field that needs to be checked in given IP. This is if the prefix size is not a multiple of 
		# 8 and this can result in a range of numbers.
		ipContents[fields - 1] = ipContents[fields - 1] & mask

		# Check prefix fields that won't have a range
		for i in range(fields):
			if ipContents[i] != IP[i]:
				valid = False
				# Set this field back to what it was before &ing with mask
				ipContents[fields-1] = original_field
				break
			if i == (fields - 1):
				return True

	return valid

# === Check if remote computer tries to connect with LAN server
#	Parameters:	source IP, destination IP
#	Output:		boolean
def tryToConnect(srcIPContents, destIPContents, validIPs):
	if (not inRange(srcIPContents, validIPs) and inRange(destIPContents, validIPs)):
		return True
	else: 
		return False

# === Check for potential DNS query
#	Parameters: Destination IP contents
#	Output: 	boolean
def queryForDns(destIPContents):
	if inRange(destIPContents, [localIP]) and int(destIPContents[4]) == 53:
		return True
	else:
		return False

# === Read in log file of packets
while True:
	# Read in malicious hosts from domain.txt
	with open('domains.txt', 'r') as file:
		malicious_hosts = [host.strip() for host in file]

	# Read in from standard input
	line = sys.stdin.readline()

	# Check for end of the log file
	if not line:
		break
	
	# Check if at the beginning of a new packet
	if line[2] == ":" and line.split()[1] == 'IP':
		ip_protocol = line.split(", ")[5].split()[1]

		# Read the next line to check src/dest IP addresses
		ipHeader = sys.stdin.readline().strip()

		# Split the ipHeader into src/dst IPs and IP fields
		ips = ipHeader.split(":")[0].split(" > ")
		fields = ipHeader.split(":")[1].strip().split(", ")

		srcIP = ips[0]
		destIP = ips[1]

		srcIPContents = map(lambda x: int(x), srcIP.split("."))
		destIPContents = map(lambda x: int(x), destIP.split("."))

		# Check attacks based on TCP packets
		if ip_protocol == "TCP":
			seq = fields[2].split()[0]
			seqValue = fields[2].split()[1]

			# If there is an initial attempt to connect during handshake, ack will not appear as a field
			if fields[3].split()[0] == "ack":
				acknowledged = True
				ackValue = fields[3].split()[1]

			# === UNAUTHORIZED ACCESS ===
			# Attempted Connection
			if tryToConnect(srcIPContents, destIPContents, ip_list) and \
					(seq == "seq" and seqValue > 1) and not acknowledged:
					print "[Attempted server connection]: " + "rem:" + srcIP + ", srv:" + destIP
				
			# Accepted Connection
			if tryToConnect(srcIPContents, destIPContents, ip_list) and \
					(seqValue == "1" and ackValue == "1"):
					print "[Accepted server connection]: " + "rem:" + srcIP + ", srv:" + destIP

		# Check attacks based on UDP packets
		if ip_protocol == "UDP":
			dns_host = ipHeader.split("? ")[1].split()[0][:-1]

			# === KNOWN MALICIOUS HOSTS ===
			if queryForDns(destIPContents) and (dns_host in malicious_hosts):
				print "[Malicious name lookup]: " + "src:" + srcIP + ", host:" + dns_host

		# === SPOOF ATTACK ===
		# Recall: at least one of the source and destination addresses should be in the 10.97.0.0/16 IP range.
		# So if they're BOTH not in the range, then there is a spoof attack
		if not inRange(srcIPContents, [localIP]) and not inRange(destIPContents, [localIP]):
			print "[Spoofed IP address]: " + "src:" + srcIP + ", dst:" + destIP
