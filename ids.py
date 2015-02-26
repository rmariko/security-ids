#!/usr/bin/python
# === A custom intrusion detection system used to monitor traffic for known
# === attacks based on provided signaures.

import sys

# === Defined IPs ===
waterlooIP = "23.91.163.0/24"
kitchenerIP = "23.91.184.0/23"

# === Boolean for handshake acknowledged
acknowledged = False

# === Check if provided IP is within LAN ===
# IP address must be of the form 10.97.*.* where * is a value from 
# 0 to 255.
def localIP(ipContents):
	if (ipContents[0] != "10" or ipContents[1] != "97") or \
			(int(ipContents[2]) < 0 or int(ipContents[2]) > 255) or \
			(int(ipContents[3]) < 0 or int(ipContents[3]) > 255):
		return False
	else:
		return True

# === Check if provided IP is within KW IP range ===
def kwIP(ipContents):
	if (ipContents[0] != "23" or ipContents[1] != "91") or \
			(ipContents[2] != "163" and ipContents[2] != "184") or \
			(ipContents[3] != "0"):
		return False
	else:
		return True

# === Check if remote computer tries to connect with LAN server
def tryToConnect(srcIPContents, destIPContents):
	if (not localIP(srcIPContents) or not kwIP(srcIPContents)) and \
			(localIP(destIPContents) or kwIP(destIPContents)):
		return True
	else: 
		return False

# === Read in log file and separate each packet
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

		srcIPContents = srcIP.split(".")
		destIPContents = destIP.split(".")

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

# === Debug Statements ===
# print(tcpdump)
# print(ipHeader)
