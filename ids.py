#!/usr/bin/python
# === A custom intrusion detection system used to monitor traffic for known
# === attacks based on provided signaures.

import sys

# === Read in the log file from stdin ===
tcpdump = sys.stdin.readlines()

# === Grab the IP information ===
ipHeader = [x for x in tcpdump[1].split(" ") if x != ""]

srcIP = ipHeader[0]
destIP = ipHeader[2][:-1]

srcIPContents = srcIP.split(".")
destIPContents = destIP.split(".")

# === Helper Function for SPOOF ===
# IP address must be of the form 10.97.*.* where * is a value from 
# 0 to 255.
def spoofIP(ipContents):
	if (ipContents[0] != "10" or ipContents[1] != "97") or \
		(ipContents[2] < 0 or ipContents[2] > 255) or \
		(ipContents[3] < 0 or ipContents[3] > 255):
		return False
	else:
		return True

# === SPOOF ATTACK ===
if not spoofIP(srcIPContents) or not spoofIP(destIPContents):
	print "[Spoofed IP address]: " + "src:" + srcIP + ", dst:" + destIP

# === Debug Statements ===

