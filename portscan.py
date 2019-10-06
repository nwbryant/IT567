# port scanner
import argparse, sys
from scapy.all import *

# output format
def print_ports(port, state):
	print("%s | %s" % (port, state))

# tcp scan
def tcp_scan(target, ports):
	print("tcp scan on, %s with ports %s" % (target, ports))
	sport = RandShort()
  traceroute(target)
	for port in ports:
		pkt = sr1(IP(dst=target)/TCP(sport=sport, dport=port, flags="S"), timeout=1, verbose=0)
		if pkt != None:
			if pkt.haslayer(TCP):
				if pkt[TCP].flags == 20:
					print_ports(port, "Closed")                    
				elif pkt[TCP].flags == 18:
					print_ports(port, "Open")
				else:
					print_ports(port, "TCP packet resp / filtered")
			elif pkt.haslayer(ICMP):
				print_ports(port, "ICMP resp / filtered")
			else:
				print_ports(port, "Unknown resp")
				print(pkt.summary())
		else:
			print_ports(port, "Unanswered")

# udp scan
def udp_scan(target, ports):
	print("udp scan on, %s with ports %s" % (target, ports))
    traceroute(target)
	for port in ports:
		pkt = sr1(IP(dst=target)/UDP(sport=port, dport=port), timeout=2, verbose=0)
		if pkt == None:
			print_ports(port, "Open / filtered")
		else:
			if pkt.haslayer(ICMP):
				print_ports(port, "Closed")
			elif pkt.haslayer(UDP):
				print_ports(port, "Open / filtered")
			else:
				print_ports(port, "Unknown")
				print(pkt.summary())

# argument setup
parser = argparse.ArgumentParser("Port scanner using Scapy")
parser.add_argument("-t", "--target", help="Specify target IP", required=True)
parser.add_argument("-p", "--ports", type=int, help="Specify port")
parser.add_argument("-mx", "--maxport", type=int, help="Specify min port")
parser.add_argument("-mn", "--minport", type=int, help="Specify max port")
parser.add_argument("-s", "--scantype", help="Scan type, tcp/udp", required=True)
args = parser.parse_args()

# arg parsing
target = args.target
scantype = args.scantype.lower()
# set ports if passed
if args.ports:
	ports = args.ports
elif args.minport and args.maxport:
    ports = range(args.minport, args.maxport)
else:
	# default port range
	ports = range(1, 1024)

# scan types
if scantype == "tcp" or scantype == "t":
	tcp_scan(target, ports)
elif scantype == "udp" or scantype == "u":
	udp_scan(target, ports)
else:
	print("Scan type not supported")
