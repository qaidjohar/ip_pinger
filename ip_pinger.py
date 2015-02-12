#!/usr/bin/python
from scapy.all import *
import re

INTERVAL = 2
conf.verb = 0

def splitIP( ipStr):

    l = re.split('(.*)\.(.*)\.(.*)\.(.*)', ipStr)
    return l[1:-1]

flag = 1
print "Welcome to the IP Pinger"
while flag != -1:
	if flag == 1:
		print "Enter the starting IP address(ex. 192.168.0.100): "
		start_ip = raw_input()
		ip_val = splitIP( start_ip )
		flag = 2
		#print str(len(ip_val))
	if flag == 2:
		print "Enter the count of IP's to scan(ex. 50): "
		ip_count = int(raw_input())

	host = int(ip_val[3])
	addr = host + ip_count
	if addr > 255:
		print "Host range exceeded beyone one network. Please try again..."
		flag = 3
		while flag == 3:
			print "Would you like to change IP (yes/no): "
			input_val = raw_input()
			if input_val.lower() == 'yes' or input_val.lower() == 'y' :
				flag = 1
			elif input_val.lower() == 'no' or input_val.lower() == 'n' :
				flag = 2
			else:
				print "invalid input\n"
				flag = 3
	else:
		flag = -1			
	
#print str(addr)
#print "Well Done!!"
count_up = 0
count_down = 0

for ip in range(int(ip_val[3]), int(addr)):
    packet = IP(dst=ip_val[0]+"."+ip_val[1]+"."+ip_val[2]+"."+ str(ip), ttl=20)/ICMP()
    reply = sr1(packet, timeout=INTERVAL)
    if not (reply is None):
         print reply.src, "is online"
         count_up += 1
    else:
         print "%s is down" % packet[IP].dst
         count_down += 1

print "=========SUMMARY========="
print "Total machines up = "+str(count_up)
print "Total machines down = "+str(count_down)
