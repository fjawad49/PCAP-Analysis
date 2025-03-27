## External Libraries

- `analysis_pcap_tcp` relies on the `dpkt` external Python library. It can be installed using the following terminal command on Windows using `pip`:

```
pip install dpkt
```

## Information on and Running webserver.py

### Overview

This program can be used to parse a PCAP file and display the following data regarding only complete TCP flows (characterized by a SYN handshake from the sender and final FIN):

- Number of Flows
- For each flow:
	- Source and Destination IP/Port information
	- First 2 transactions from sender to receiver, specfically:
		- Sequence Number
		- Acknowledgement Number
		- Window Size
	- Throughput
	- First 3 congestion window sizes
	- Number of triple duplicate ACK retransmissions
	- Number of timeout retransmissions

### Running the Program

1. To run this program simply run the following command on your terminal:
```
python analysis_pcap_tcp.py
```

2. You will then be prompted to enter the file name/path of the PCAP. If the file is not a PCAP file, you will be reprompted to enter a valid PCAP file name/path. If the file does not exist, an error will be thrown.

3. The program will automatically parse the complete TCP flows from the file and print out the data.

## Program Logistics

### Determining Transactions

To determine the first two transactions, the program filters out SYN packets and handshake related ACK packets. THe first two transactions are the first two packets that follow.

**Determining Window Size**: Given that the window size scale factor is located in SYN packets, the program records the window size factor value during the handshake. This value is then retrieve and used as a multiplicative factor for calculating the window size in a packet.

### Determining Throughput
The throughput is determined by dividing the total bytes sent by the sender and divding it by the TCP connection time period.

**TCP Connection Time:** To determine throughput the program keeps track of the time the very first SYN packet sent by the sender was detected and the last packet sent by the sender was detected. The end time is subtracted by the start time to determine to flow interval.

**Bytes Sent:** To determine the total bytes sent by the sender, the program keeps track of the total sum of the length of each TCP header and payload.

### Determining Congestion Window Size
Calculating the congestion window size empirically is different considering values such as the initial size and ssthresh is unknown. This program calculates congestion window sizes at RTT intervals by first keeping track of a start interval time using the current packet timestamp. Then once about RTT time has passed the program, the maximum number of in-flight packets is determined to be the estimated congestion window size, and then the start time for the interval is reset to the current timestamp.

**RTT:** To estimate RTT, the following formula is used to recaclulate an average RTT each time an ACK is received from the sender for α = 0.125:

**Max In-Flight Packets:** During each interval, anytime a packet is sent, the program calculates if the current number of in-flight packets is the maximum for the interval. If so, the value is recorded. At the end of an interval, when the congestion window size is recorded, the maximum in-flight packets is set to the current number of in-flight packets.


<p align="center">
  Average RTT = (1-α)RTT + α(NEW_RTT)
</p>

### Determining Packet Retransmissions
Given that TCP utilizes cumulative ACKs, the program keeps track of the most recently ACKed packet, and the number of ACKs received for the packet. Additionally, the program keeps track of all in-flight/sent packets. If a retransmission is sent for a packet, then the program determines if **(1)** at least 3 duplicate ACKs were received for the packet with an acknowledgment number identical to the sequence number of the resent packet, indicating a triple duplicate ACK, or **(2)** else the retransmission is determined to be due to a timeout.

