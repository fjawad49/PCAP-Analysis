import dpkt, sys, socket

file_path = input("Please enter a valid PCAP file name or path: ")
file_path = "assignment2.pcap"
# Ensure file is of right extension
while not file_path.endswith(".pcap") and not file_path.endswith(".pcap/"):
	file_path = input("Invalid file type. Please enter a valid PCAP file name or path: ")

pcap_file = None
# Test if file exists
try:
	pcap_file = open(file_path, "rb")
except Exception as e:
	print(e)
	print("Could not open, not a valid readable file.")
	# Exit program
	sys.exit(1)

pcap = dpkt.pcap.Reader(pcap_file)

# Stores known TCP flows using 4-tuple identifier/key of source IP, source port, destine IP, and destination port
tcp_flows = dict()

# Remove finished flows and place them into this array (allows reuse of ports)
inactive_flows = []

# Keep a record of number of flows (must begin with SYN handshake and end with FIN from receiver)
num_flows = 0

"""
Parses a TCP segment to retrieve window scall factor from options.

Parameters:
	tcp: A TCP object from the dpkt library
"""
def retrieve_scale_factor(tcp):
	tcp_opts = dpkt.tcp.parse_opts(tcp.opts)
	scale = 0
	for opt in tcp_opts:
		if opt[0] == dpkt.tcp.TCP_OPT_WSCALE:
			scale = opt[1]
	return scale
"""
Parses a segment from an exisiting TCP flow and adds respective information to the TCPdictionary.

Parameters:
	flow_identifier: 4-tuple key for flow in dictionary of source IP, source port, destine IP, and destination port
"""
def parse_flow_segment(flow_identifier, timestamp):
	# Add all sent bytes including TCP header and data, EXCLUDING final ACK after receiving FIN/ACK
	tcp_flows[flow_identifier]["data_sent"] += len(tcp)
	tcp_flows[flow_identifier]["sent_packets"] += 1
	
	if tcp_flows[flow_identifier]["con_interval_start"] == None and tcp.flags & dpkt.tcp.TH_SYN == 0:
		tcp_flows[flow_identifier]["con_interval_start"] = timestamp
		if (flow_identifier[1] == 43498):
			print("SETTTTT", tcp_flows[flow_identifier]["con_interval_start"])
	
	# Check if first two transactions added. If not, parsed packet is one of first 2 transactions. Ensure packet is not an empty ACK
	if (tcp_flows[flow_identifier]["seq1"] == -1 or tcp_flows[flow_identifier]["seq2"] == -1) and (tcp.flags & dpkt.tcp.TH_ACK and len(tcp.data) != 0):
		transaction_num = "2"
		if tcp_flows[flow_identifier]["seq1"] == -1:
			transaction_num = "1"
		
		
		tcp_flows[flow_identifier][f"seq{transaction_num}"] = tcp.seq
		tcp_flows[flow_identifier][f"ack{transaction_num}"] = tcp.ack
		# Scale factor can be represented as 2^scale, so use bitwise operations to retrieve window size
		tcp_flows[flow_identifier][f"win{transaction_num}"] = tcp.win * (1 << int.from_bytes(tcp_flows[flow_identifier]["win_factor"], 'big'))
	
	# Map new sequence numbers to an entry that keeps track of acks received per seq and sent timestamps
	
	next_seq_num = 0
	if tcp.flags & dpkt.tcp.TH_SYN:
		next_seq_num = tcp.seq + 1
	else:
		next_seq_num = tcp.seq + len(tcp.data)
		
	if next_seq_num > tcp.seq:
		seq_index = -1
		sent_seq_nums = tcp_flows[flow_identifier]["sent_seq_nums"]
		for index in range(len(sent_seq_nums)):
			if sent_seq_nums[index][0] == tcp.seq:
				seq_index = index
				break
		if seq_index == -1:
			tcp_flows[flow_identifier]["sent_seq_nums"].append((tcp.seq, 0, timestamp, next_seq_num))
		else:
			current_seq_tuple = tcp_flows[flow_identifier]["sent_seq_nums"][seq_index]
			tcp_flows[flow_identifier]["sent_seq_nums"][seq_index] = (tcp.seq, 0, current_seq_tuple[2], current_seq_tuple[3])
		if i < 20 and flow_identifier[1] == 43498:
			pass
			#print(f"---index: {seq_index} and next_Seq_num: {next_seq_num}---SEQ NUM LIST-------------{tcp_flows[flow_identifier]["sent_seq_nums"]}-------sent packets: {len(tcp_flows[flow_identifier]["sent_seq_nums"])}")
i = 0
		
def eval_cwnd(flow_identifier, tcp, receive_time):
	if tcp.flags & dpkt.tcp.TH_ACK:
		seq_index = -1
		sent_seq_nums = tcp_flows[flow_identifier]["sent_seq_nums"]
		for index in range(len(sent_seq_nums)):
			if sent_seq_nums[index][3] == tcp.ack:
				seq_index = index
				break
				
		new_rtt = receive_time - sent_seq_nums[seq_index][2]
		rtt = tcp_flows[flow_identifier]["RTT"]
		
		global i
		if i < 20 and tcp.dport == 43498:

			print(f"Receive ack: {tcp.ack} at {receive_time}, {flow_identifier}", i)
			i+=1
		if rtt:
			alpha = 0.125
			tcp_flows[flow_identifier]["RTT"] = (1-alpha)*rtt + alpha*new_rtt
		else:
			tcp_flows[flow_identifier]["RTT"] = new_rtt
		
		sent_seq_nums = sent_seq_nums[seq_index+1:]
		tcp_flows[flow_identifier]["sent_packets"] = len(sent_seq_nums)
		if i < 20 and tcp.dport == 43498:
			pass
			#print(f"---index: {seq_index}---SEQ NUM LIST-------------{sent_seq_nums}-------sent packets: {len(sent_seq_nums)}")
		tcp_flows[flow_identifier]["sent_seq_nums"] = sent_seq_nums


# Use dpkt library to iterate through packets in PCAP file
for timestamp, data in pcap:
	# Retrieve IP datagram from ethernet frame, and make sure it is an IP packet
	ip = dpkt.ethernet.Ethernet(data).data
	if (type(ip) != dpkt.ip.IP):
		continue
	# Retrieve TCP segment from IP datagram, and make sure it is a TCP packet
	tcp = ip.data
	if (type(tcp) != dpkt.tcp.TCP):
		continue
	
	# Ensure TCP protocol for IP packet
	if ip.p == dpkt.ip.IP_PROTO_TCP:
		# Src IP, src port, dst IP, dst port unique identifier for flow
		flow_identifier = (socket.inet_ntoa(ip.src), tcp.sport, socket.inet_ntoa(ip.dst), tcp.dport)
		
		# Check if flow from sender already exists, do not create one on the receiver side
		alt_flow_identifier = (socket.inet_ntoa(ip.dst), tcp.dport, socket.inet_ntoa(ip.src), tcp.sport)
		if alt_flow_identifier in tcp_flows:
			flow_identifier = alt_flow_identifier
			eval_cwnd(flow_identifier, tcp, timestamp)
		
		# Add flow to TCP flows dictionary if sender is establishing a handshake and flow does not exist
		if tcp.flags & dpkt.tcp.TH_SYN and flow_identifier not in tcp_flows:
			# Retrieve receive window scale factor, which is only found in the handshake
			scale = retrieve_scale_factor(tcp)
			
			# Create TCP flow object with default values
			tcp_flows[flow_identifier] = {"data_sent" : 0, "win_factor": scale, "seq1": -1, "ack1": -1, "win1": -1, "seq2": -1, "ack2": -1, "win2": -1, "start_time": timestamp, "flow_fin":False, "RTT": None, "sent_seq_nums": [], "sent_packets": 1, "con_interval_start": None, "cwnd_sizes": []}
		
		# Only parse flows established within the PCAP file
		if flow_identifier not in tcp_flows:
			continue
		
		flow = tcp_flows[flow_identifier]
		# Check if sender already sent a FIN packet and ACK was sent separately
		if tcp_flows[flow_identifier]["flow_fin"] and tcp.flags & dpkt.tcp.TH_ACK and socket.inet_ntoa(ip.src) == flow_identifier[0]:	
			parse_flow_segment(flow_identifier, timestamp)
			tcp_flows[flow_identifier]["end_time"] = timestamp
			num_flows += 1
			# Remove flow from TCP flows dict so ports can be reused
			inactive_flows.append((flow_identifier, tcp_flows[flow_identifier]))
			del tcp_flows[flow_identifier]
			continue
		
		# Check if sender IP
		if socket.inet_ntoa(ip.src) == flow_identifier[0]:
			if i < 20 and tcp.sport == 43498:
				print(f"Send seq: {tcp.seq} at {timestamp}, {i}")
				i+=1
			parse_flow_segment(flow_identifier, timestamp)
		
		if tcp_flows[flow_identifier]["con_interval_start"] and (timestamp - tcp_flows[flow_identifier]["con_interval_start"] > tcp_flows[flow_identifier]["RTT"]):
			tcp_flows[flow_identifier]["cwnd_sizes"].append(tcp_flows[flow_identifier]["sent_packets"])
			if (i<20 and (tcp.sport == 43498 or tcp.dport == 43498)):
				print(f"CWND SIZE: {tcp_flows[flow_identifier]["cwnd_sizes"]}", (timestamp),(tcp_flows[flow_identifier]["con_interval_start"]), tcp_flows[flow_identifier]["RTT"])
				print(tcp_flows[flow_identifier]["sent_seq_nums"])
			tcp_flows[flow_identifier]["con_interval_start"] = timestamp
		
		# Check if receiver sends a FIN packet
		if tcp.flags & dpkt.tcp.TH_FIN and socket.inet_ntoa(ip.src) == flow_identifier[2]:
			tcp_flows[flow_identifier]["flow_fin"] = True
			# Check if packet also includes a receiver ACK, which it must at some point for the flow to end. End time is determined by final receiver ACK.
			if tcp.flags & dpkt.tcp.TH_ACK:	
				tcp_flows[flow_identifier]["end_time"] = timestamp
				num_flows += 1
				inactive_flows.append((flow_identifier, tcp_flows[flow_identifier]))
				del tcp_flows[flow_identifier]
		

# Index flows
flow_count = 1
print(f"Total Flows: {num_flows}\n")
for flow, info in inactive_flows:
	print(f"TCP FLOW {flow_count}")
	print(f"Source Port: {flow[1]}\nSource IP: {flow[0]}\nDestination Port: {flow[3]}\nDestination IP: {flow[2]}\n")
	if(info["seq1"] > -1):
		print(f"Transaction 1\nSequence Number: {info["seq1"]}\nAcknowledgment Number: {info["ack1"]}\nWindow Size: {info["win1"]}\n")
	if(info["seq2"] > -1):
		print(f"Transaction 2\nSequence Number: {info["seq2"]}\nAcknowledgment Number: {info["ack2"]}\nWindow Size: {info["win2"]}\n")
	print(f"Throughput: {info["data_sent"]/(info["end_time"]-info["start_time"])}\n")
	print("--------------------------------------\n")
	flow_count += 1
		
