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
	tcp: The segment of data type TCP from library dpkt.
"""
def retrieve_scale_factor(tcp):
	tcp_opts = dpkt.tcp.parse_opts(tcp.opts)
	scale = 0
	for opt in tcp_opts:
		if opt[0] == dpkt.tcp.TCP_OPT_WSCALE:
			scale = opt[1]
	return scale
"""
Parses a segment from an exisiting TCP flow that the SENDER sent and adds respective information to the TCP flow dictionary.

Parameters:
	flow_identifier: 4-tuple key for flow in dictionary of source IP, source port, destine IP, and destination port.
	timestamp: The timestamp indicating the time the packet was detected.
	tcp: The segment of data type TCP from library dpkt.
"""
def parse_flow_segment(flow_identifier, timestamp, tcp):
	# Add all sent bytes including TCP header and data
	tcp_flows[flow_identifier]["data_sent"] += len(tcp)
	
	# Set first start time for determining cogestion window after the SYN handshake (i.e. after estimating RTT)
	if tcp_flows[flow_identifier]["con_interval_start"] == None and tcp.flags & dpkt.tcp.TH_SYN == 0:
		tcp_flows[flow_identifier]["con_interval_start"] = timestamp
	
	
	
	# Check if first two transactions added. If not, parsed packet is one of first 2 transactions. Ensure packet is not an empty ACK from sender
	if (tcp_flows[flow_identifier]["seq1"] == -1 or tcp_flows[flow_identifier]["seq2"] == -1) and (tcp.flags & dpkt.tcp.TH_ACK and len(tcp.data) != 0):
		transaction_num = "2"
		if tcp_flows[flow_identifier]["seq1"] == -1:
			transaction_num = "1"
		
		tcp_flows[flow_identifier][f"seq{transaction_num}"] = tcp.seq
		tcp_flows[flow_identifier][f"ack{transaction_num}"] = tcp.ack
		# Scale factor can be represented as 2^scale, so use bitwise operations to retrieve window size
		tcp_flows[flow_identifier][f"win{transaction_num}"] = tcp.win * (1 << int.from_bytes(tcp_flows[flow_identifier]["win_factor"], 'big'))
	
	
	
	# Map new sequence numbers to an entry that keeps track of ACKs received per SEQ and sent timestamps
	next_seq_num = 0
	
	if tcp.flags & dpkt.tcp.TH_SYN:
		# ACK returned for SYN packet should be SEQ + 1
		next_seq_num = tcp.seq + 1
	else:
		next_seq_num = tcp.seq + len(tcp.data)
	
	# Only keep track of sent sequence numbers that expect an ACK (i.e. ignores empty ACKs from sender after SYN handshake)
	if next_seq_num > tcp.seq:
		# Find index of sent sequence number, if any
		seq_index = -1
		sent_seq_nums = tcp_flows[flow_identifier]["sent_seq_nums"]
		for index in range(len(sent_seq_nums)):
			if sent_seq_nums[index][0] == tcp.seq:
				seq_index = index
				break
		
		# Sequence number being send for the first time
		if seq_index == -1:
			tcp_flows[flow_identifier]["sent_seq_nums"].append([tcp.seq, 0, timestamp, next_seq_num])
		
		# Indicates sequence number already sent before, packet retransmission
		else:
			# Find number of total ACKs sent for sequence number (including duplicates)
			acks_index = -1
			for index in range(len(sent_seq_nums)):
				if sent_seq_nums[index][3] == tcp.seq:
					acks_index = index
					break
			
			
			# If at least 3 duplicate ACKs, retransmission is due to Triple Duplicate ACK, else timeout
			if sent_seq_nums[acks_index][1] >= 4:
				tcp_flows[flow_identifier]["triple_dup_acks"] += 1
			else:
				tcp_flows[flow_identifier]["timeouts"] += 1
			
			# Reset received ACK counter
			sent_seq_nums[acks_index][1] = 0
	
	# Keep track of total in flight packets for congestion window estimation
	sent_seq_nums = tcp_flows[flow_identifier]["sent_seq_nums"]
	num_packets = len(sent_seq_nums) if sent_seq_nums [0][1] < 1 else len(sent_seq_nums) - 1
	# Set estimated congestion window size to greatest # sent packets within interval
	if tcp_flows[flow_identifier]["sent_packets"] < num_packets:
		tcp_flows[flow_identifier]["sent_packets"] = num_packets
"""
Parses an ACK segment from an exisiting TCP flow that the RECEIVER sent and adds respective information to the TCP flow dictionary.

Parameters:
	flow_identifier: 4-tuple key for flow in dictionary of source IP, source port, destine IP, and destination port.
	tcp: The segment of data type TCP from library dpkt.
	receive_time: The timestamp indicating the time the packet was detected.
"""
def eval_ack(flow_identifier, tcp, receive_time):
	# Check to make sure packet is an ACK segment
	if tcp.flags & dpkt.tcp.TH_ACK:
		# Find index of sequence number corresponding to ACK in list of in flight packets
		seq_index = -1
		sent_seq_nums = tcp_flows[flow_identifier]["sent_seq_nums"]
		for index in range(len(sent_seq_nums)):
			if sent_seq_nums[index][3] == tcp.ack:
				seq_index = index
				break
		
		# Determine RTT for current ACKed packet
		new_rtt = receive_time - sent_seq_nums[seq_index][2]
		rtt = tcp_flows[flow_identifier]["RTT"]
		
		# Increment number of ACKs received for packet
		sent_seq_nums[seq_index][1] += 1

		# Approximate an average RTT upon receiving an ACK using the packet's RTT
		if rtt:
			alpha = 0.125
			# Do not reapproximate RTT for duplicate ACKs
			if sent_seq_nums[seq_index][1] < 2:
				tcp_flows[flow_identifier]["RTT"] = (1-alpha)*rtt + alpha*new_rtt
		else:
			tcp_flows[flow_identifier]["RTT"] = new_rtt
		
		# Account for cumulative ACKs, start in flight packet list at current ACKed sequence number
		sent_seq_nums = sent_seq_nums[seq_index:]
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
			eval_ack(flow_identifier, tcp, timestamp)
		
		
		
		# Add flow to TCP flows dictionary if sender is establishing a handshake and flow does not exist
		if tcp.flags & dpkt.tcp.TH_SYN and flow_identifier not in tcp_flows:
			# Retrieve receive window scale factor, which is only found in the handshake
			scale = retrieve_scale_factor(tcp)
			
			# Create TCP flow object with default values
			tcp_flows[flow_identifier] = {"flow_identifier": flow_identifier, "data_sent" : 0, "win_factor": scale, "seq1": -1, "ack1": -1, "win1": -1, "seq2": -1, "ack2": -1, "win2": -1, "start_time": timestamp, "flow_fin":False, "RTT": None, "sent_seq_nums": [], "sent_packets": 1, "con_interval_start": None, "cwnd_sizes": [], "triple_dup_acks": 0, "timeouts": 0}
		
		
		
		# Only parse flows established within the PCAP file
		if flow_identifier not in tcp_flows:
			continue
			
		

		flow = tcp_flows[flow_identifier]
		# Check if sender already sent a FIN packet and ACK was sent separately afterwards
		if flow["flow_fin"] and tcp.flags & dpkt.tcp.TH_ACK and socket.inet_ntoa(ip.src) == flow_identifier[0]:	
			parse_flow_segment(flow_identifier, timestamp, tcp)
			flow["end_time"] = timestamp
			continue
		
		
		
		# Check if sender IP, if so, parse sent packet
		if socket.inet_ntoa(ip.src) == flow_identifier[0]:
			parse_flow_segment(flow_identifier, timestamp, tcp)


	
		# Estimate first 3 congestion window sizes at approximately RTT intervals
		if len(flow["cwnd_sizes"]) < 3 and tcp_flows[flow_identifier]["con_interval_start"] and (timestamp - tcp_flows[flow_identifier]["con_interval_start"] > tcp_flows[flow_identifier]["RTT"]):

			# Approximate cwnd using current maximum in-flight packets during interval
			flow["cwnd_sizes"].append(tcp_flows[flow_identifier]["sent_packets"])
			
			# Set start time of new interval to current packet timestamp and reset estimate congestion window to current sent_seq_nums length
			flow["con_interval_start"] = timestamp
			flow["sent_packets"] = len(flow["sent_seq_nums"])
		
		
		
		# Check if receiver sends a FIN packet
		if tcp.flags & dpkt.tcp.TH_FIN and socket.inet_ntoa(ip.src) == flow_identifier[2]:
			flow["flow_fin"] = True
			# Check if packet also includes a receiver ACK, which it must at some point for the flow to end. End time is determined by final receiver ACK.
			if tcp.flags & dpkt.tcp.TH_ACK:	
				flow["end_time"] = timestamp
				num_flows += 1

# Index flows
flow_count = 1
print(f"Total Flows: {num_flows}\n")
for identifier, info in tcp_flows.items():
	# Only print finished flows (according to homework definition of a TCP flow)
	if (info["flow_fin"]):
		print(f"TCP FLOW {flow_count}")
		print(f"Source Port: {identifier[1]}\nSource IP: {identifier[0]}\nDestination Port: {identifier[3]}\nDestination IP: {identifier[2]}\n")
		
		if(info["seq1"] > -1):
			print(f"Transaction 1\nSequence Number: {info["seq1"]}\nAcknowledgment Number: {info["ack1"]}\nWindow Size: {info["win1"]}\n")
			
		if(info["seq2"] > -1):
			print(f"Transaction 2\nSequence Number: {info["seq2"]}\nAcknowledgment Number: {info["ack2"]}\nWindow Size: {info["win2"]}\n")
			
		print(f"Throughput: {info["data_sent"]/(info["end_time"]-info["start_time"])}\n")
		
		cwnd_comment = ""
		last_cwnd = -1
		for i in range(len(info["cwnd_sizes"])):
			if last_cwnd == -1:
				last_cwnd = info["cwnd_sizes"][i]
				continue
			if info["cwnd_sizes"][i] > last_cwnd and (cwnd_comment == "Increasing" or cwnd_comment == ""):
				cwnd_comment = "Increasing"
				last_cwnd = info["cwnd_sizes"][i]
				continue
			elif info["cwnd_sizes"][i] < last_cwnd and (cwnd_comment == "Decreasing" or cwnd_comment == ""):
				cwnd_comment = "Decreasing"
				last_cwnd = info["cwnd_sizes"][i]
				continue
			else:
				cwnd_comment = "Fluctuating"
				break
		print(f"Congestion Window Sizes (# Packets): {info["cwnd_sizes"]}. {cwnd_comment}{" Congestion Window Sizes" if cwnd_comment else ""}\nTriple Duplicate Ack Retransmissions: {info["triple_dup_acks"]}\nTimeout Retransmissions: {info["timeouts"]}")
		print("--------------------------------------\n")
	flow_count += 1
		
