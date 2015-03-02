#!/usr/bin/python
# === A custom intrusion detection system used to monitor traffic for known
# === attacks based on provided signaures.

import sys
import math
import re
from datetime import datetime

############################
# === GLOBAL DEFINITIONS ===
############################

# === List of Valid IPs ===
waterloo_IP = "23.91.163.0/24"
kitchener_IP = "23.91.184.0/23"
local_IP = "10.97.0.0/16"

ip_list = [waterloo_IP, kitchener_IP, local_IP]

# === IP header fields ===
ip_fields = {}

# === Boolean for handshake acknowledged ===
acknowledged = False

# === Dictionary for timestamp comparison and destination comparison ===
src_random_scan = {}
src_time = {}

# === Code Red Worm Signature ===
code_red_regex = 'GET.\/default.ida\?[N]+%u9090%u6858%ucbd3%u7801%u9090%u6858%ucbd3%u7801%u9090%u6858%ucbd3%u7801%u9090%u9090%u8190%u00c3%u0003%u8b00%u531b%u53ff%u0078%u0000%u00=a..HTTP\/1.0'

# === A packets contents ===
packet_contents = ""

# === src and dest addresses and ports ===
src_IP = None
dest_IP = None

src_port = None
dest_port = None

# === DNS host request ===
dns_host = None

# === Read in malicious hosts from domain.txt
with open('domains.txt', 'r') as file:
	malicious_hosts = [host.strip() for host in file]

##################################################
# === HELPER FUNCTIONS FOR IDENTIFYING ATTACKS ===
##################################################

# === Function used to later determine if IPs are within another IP's range
# Given an IP in the form of CIDR find the number of IP fields to check 
# as well as a mask used to determine if a given field is in range of an IP
# address. 
#	Parameters: string -- ip address 
#	Output: 	tuple -- # of fields to check in an ip prefix, mask # used to '&'' with 
#				IP field to check based on prefix size
def get_IP_mask_field(ip):
	data = ip.split("/")
	prefix_size = data[1]
	fields_to_check = math.ceil(int(prefix_size)/8)

	mask = 255 if ((int(prefix_size) % 8) == 0) else (~ ((1 << (8 - (int(prefix_size) % 8))) - 1))

	return (int(fields_to_check), mask)

# === Check if a provided IP address is within KW IP range ===
#	Parameters:	list of ints -- contents of an ip address
#	Output:		boolean
def in_range(ip_contents, valid_IPs):
	valid = True

	for valid_IP in valid_IPs:
		data = valid_IP.split("/")
		IP = map(lambda x: int(x), data[0].split("."))

		# Grab the number of fields to check in IP prefix and the mask used to check 
		# if 'the field to check' is in range
		fields, mask = get_IP_mask_field(valid_IP)

		original_field = ip_contents[fields-1]
		# Field that needs to be checked in given IP. This is if the prefix size is not a multiple of 
		# 8 and this can result in a range of numbers.
		ip_contents[fields - 1] = ip_contents[fields - 1] & mask

		# Check prefix fields that won't have a range
		for i in range(fields):
			if ip_contents[i] != IP[i]:
				valid = False
				# Set this field back to what it was before &ing with mask
				ip_contents[fields-1] = original_field
				break
			if i == (fields - 1):
				return True

	return valid

# === Check if remote computer tries to connect with LAN server
#	Parameters:	source IP, destination IP
#	Output:		boolean
def try_to_connect(src_IP_contents, dest_IP_contents, valid_IPs):
	if (not in_range(src_IP_contents, valid_IPs) and in_range(dest_IP_contents, valid_IPs)):
		return True
	else: 
		return False

# === Check for potential DNS query
#	Parameters: Destination IP contents
#	Output: 	boolean
def query_for_dns(dest_IP_contents):
	if in_range(dest_IP_contents, [local_IP]) and dest_IP_contents[4] == 53:
		return True
	else:
		return False

# === Function used to compare timestamps
def time_diff(time1, time2):
	t1 = datetime.strptime(time1, "%H:%M:%S")
	t2 = datetime.strptime(time2, "%H:%M:%S")

	difference = t2 - t1

	return difference.seconds

########################################
# === BEGIN TO PARSE TCPDUMP PACKETS ===
########################################
while True:

	# Read in from standard input
	header = sys.stdin.readline().strip()

	# Check for end of the log file
	if not header:
		break

	# Parse packet contents
	if header.split(":")[0][1] == "x":
		hex_to_text = header.rsplit(" ", 1)[1]
		packet_contents += hex_to_text
	
	# Check if at the beginning of a new packet
	if header[2] == ":" and header.split()[1] == 'IP':		

		# If we have reached the beginning of a new packet; we need to parse previous
		# packet contents now for CODE RED WORM
		if packet_contents != "":
			if re.search(code_red_regex, packet_contents) and dest_port == 80:
				print "[Code Red exploit]: src:" + src_IP + ", dst:" + dest_IP
			
			# Reset packet contents for next packet
			packet_contents = ""

		ip_protocol = header.split(", ")[5].split()[1]

		# Read the next line to check src/dest IP addresses
		IP_header = sys.stdin.readline().strip()

		# Split the IP_header into src/dst IPs and IP fields
		ips = IP_header.split(":")[0].split(" > ")

		if ip_protocol == "TCP":
			fields = IP_header.split(":")[1].strip().split(", ")
		else:
			# Difficulty with splitting on [udp sum ..]
			parsed_ip_header = IP_header.split("[")[1].strip().split("] ")
			if len(parsed_ip_header) == 1:
				field1 = parsed_ip_header[0]
				fields = [field1]
			else:
				field1 = parsed_ip_header[0]
				field2 = parsed_ip_header[1].split()

				# Concatenate A? and it's request host
				if "A?" in field2:
					index = field2.index("A?")
					host = field2[index+1]
					dns_host = host[:-1]
					field2[index] = "A? " + host
					field2.remove(host)

				# Concatenate both field lists
				fields = [field1] + field2

		# Add fields to a dictionary
		for field in fields:
			if ip_protocol == "TCP":
				if field.split()[0] == 'options':
					ip_fields[field.split()[0]] = field.split("[")[1][:-1]
				else:
					ip_fields[field.split()[0]] = field.split()[1]
			else:
				if field.split()[0] == "A?":
					ip_fields["A?"] = field.split()[1]
				else:
					ip_fields[field] = ""

		# Packet src and dest IP addresses/ports
		src_IP = ips[0]
		dest_IP = ips[1]

		src_IP_contents = map(lambda x: int(x), src_IP.split("."))
		dest_IP_contents = map(lambda x: int(x), dest_IP.split("."))

		src_port = src_IP_contents[4]
		dest_port = dest_IP_contents[4]

		# Packet's timestamp
		timestamp = header.split()[0].split(".")[0]

		# === SPOOF ATTACK ===
		# Recall: at least one of the source and destination addresses should be in the 10.97.0.0/16 IP range.
		# So if they're BOTH not in the range, then there is a spoof attack
		if not in_range(src_IP_contents, [local_IP]) and not in_range(dest_IP_contents, [local_IP]):
			print "[Spoofed IP address]: " + "src:" + src_IP + ", dst:" + dest_IP

		# === RANDOM SCANNING ===
		if src_IP not in src_random_scan:
			src_random_scan[src_IP] = [dest_IP]
			src_time[src_IP] = timestamp
		else:
			if dest_IP not in src_random_scan[src_IP]:
				# Check for 10 requests within two second period
				if (len(src_random_scan[src_IP]) == 9) and (time_diff(timestamp, src_time[src_IP]) <= 2):
					print "[Potential random scan]: att:" + src_IP.rsplit(".", 1)[0]
				else:
					src_random_scan[src_IP].append(dest_IP)
					src_time[src_IP] = timestamp

		# Check attacks based on TCP packets
		if ip_protocol == "TCP":

			# If there is an initial attempt to connect during handshake, ack will not appear as a field
			if "ack" in ip_fields.keys():
				acknowledged = True
				ack_value = ip_fields["ack"]

			# === UNAUTHORIZED ACCESS ===
			# Attempted Connection
			if try_to_connect(src_IP_contents, dest_IP_contents, ip_list) and \
				("seq" in ip_fields.keys()) and int(ip_fields["seq"]) > 1 and not acknowledged:
					print "[Attempted server connection]: " + "rem:" + src_IP + ", srv:" + dest_IP
				
			# Accepted Connection
			if try_to_connect(src_IP_contents, dest_IP_contents, ip_list) and \
					("seq" in ip_fields.keys()) and ("ack" in ip_fields.keys()) and int(ip_fields["seq"]) == 1 and int(ip_fields["ack"]) == 1:
					print "[Accepted server connection]: " + "rem:" + src_IP + ", srv:" + dest_IP

		# Check attacks based on UDP packets
		if ip_protocol == "UDP":
			# Check for resource record of TypeA
			if "A?" in ip_fields.keys():
				# === KNOWN MALICIOUS HOSTS ===
				if query_for_dns(dest_IP_contents) and (dns_host in malicious_hosts):
					print "[Malicious name lookup]: " + "src:" + src_IP + ", host:" + dns_host
