# CSc 361: Computer Communications and Networks (Spring 2016)
## Assignment 3 - README

https://courses1.csc.uvic.ca/courses/2016/spring/csc/361

### Requirements
pcap library: libpcap, libpcap-dev

### Assumptions
For the purpose of simplifying the problem, we will assume that
  - two traceroute commands will not overlap in the packet stream if they have
    the same ip.dst and ip.src
  - the traceroute will use all standard plags with the exception of the
    UDP/ICMP select flag
  -
  -
  -
  -

### Compiling
```bash
$ make
```

### Running
```bash
$ ./run <capture file>
```

### Notes
Useful Filters
 - ip.flags.mf==1 || ip.frag_offset>0
 - ip.src==<source address> && ip.dst==<destination address>



CSc 361: Computer Communications and Networks 1
(Spring 2016) 2
3 Assignment 3: Analysis of IP Protocol
4 Spec Out: March 1, 2016
5 Due: 3:30 pm March 25, 2016
6 1 Goal
7 The purpose of this assignment is to learn about the IP protocol. You are required to write a C
8 program with the pcap library to analyze a trace of IP datagrams.
9 2 Introduction
10 In this assignment, we will investigate the IP protocol, focusing on the IP datagram. Well do so
11 by analyzing a trace of IP datagrams sent and received by an execution of the traceroute program.
12 Well investigate the various elds in the IP datagram, and study IP fragmentation in detail.
13 A background of the traceroute program is summarized as follows. The traceroute program
14 operates by rst sending one or more datagrams with the time-to-live (TTL) eld in the IP header
15 set to 1; it then sends a series of one or more datagrams towards the same destination with a TTL
16 value of 2; it then sends a series of datagrams towards the same destination with a TTL value of 3;
17 and so on. Recall that a router must decrement the TTL in each received datagram by 1 (actually,
18 RFC 791 says that the router must decrement the TTL by at least one). If the TTL reaches 0, the
19 router returns an ICMP message (type 11 TTL-exceeded) to the sending host. As a result of this
20 behavior, a datagram with a TTL of 1 (sent by the host executing traceroute) will cause the router
21 one hop away from the sender to send an ICMP TTL-exceeded message back to the sender; the
22 datagram sent with a TTL of 2 will cause the router two hops away to send an ICMP message back
23 to the sender; the datagram sent with a TTL of 3 will cause the router three hops away to send an
24 ICMP message back to the sender; and so on. In this manner, the host executing traceroute can
25 learn the identities of the routers between itself and a chosen destination by looking at the source
26 IP addresses in the datagrams containing the ICMP TTL-exceeded messages. You will be provided
27 with a trace le created by traceroute.
28 Of course, you can create a trace le by yourself. Note that when you create the trace le,
29 you need to use dierent datagram sizes (e.g., 2500 bytes) so that the captured trace le includes
30 information on fragmentation.
31 3 Requirement
32 You are required to write a C program with the pcap library to analyze the trace of IP datagrams
33 by an execution of traceroute. To make terminologies consistent, in this assignment we call the
1
source 34 node as the computer that executes traceroute. The ultimate destination node refers to the
35 host that is the ultimate destination dened when running traceroute. For example, the ultimate
36 destination node is \mit.edu" when you run
37 %traceroute mit.edu 2000
38 In addition, an intermediate destination node refers to the router that is not the ultimate destination
39 node but sends back a ICMP message to the source node.
40 Your program needs to output the following information:
41  List the IP address of the source node, the IP address of ultimate destination node, the IP
42 address(es) of the intermediate destination node(s). If multiple the intermediate destination
43 nodes exist, they should be ordered by their hop count to the source node in the increasing
44 order.
45  Check the IP header of all datagrams in the trace le, and list the set of values in the protocol
46 eld of the IP headers. Note that only dierent values should be listed in a set.
47  How many fragments were created from the original datagram? Note that 0 means no frag-
48 mentation. Print out the oset (in terms of bytes) of the last fragment of the fragmented IP
49 datagram. Note that if the datagram is not fragmented, the oset is 0.
50  Calculate the average and standard deviation of round trip time(s) between the source node
51 and the intermediate destination node (s) and the average round trip time between the source
52 node and the ultimate destination node. The average and the average and standard deviation
53 are calculated over all fragments sent/received between the source nodes and the (interme-
54 diate/ ultimate) destination node. Note that if no fragmentation happened, the standard
55 deviation is 0.
56 The output format is as follows: (Note that the values do not correspond to any trace le).
57 The IP address of the source node: 192.168.1.12
58 The IP address of ultimate destination node: 10.216.216.2
59 The IP addresses of the intermediate destination nodes:
60 router 1: 24.218.01.102,
61 router 2: 24.221.10.103,
62 router 3: 10.215.118.1.
63
64 The values in the protocol field of IP headers:
65 1: ICMP
66 17: UDP
67
68
69 The number of fragments created from the original datagram is: 3
70 The offset of the last fragment is: 3680
71
72 The avg RRT between 192.168.1.12 and 24.218.01.102 is: 50 ms, the s.d. is: 5 ms
73 The avg RRT between 192.168.1.12 and 24.221.10.103 is: 100 ms, the s.d. is: 6 ms
74 The avg RRT between 192.168.1.12 and 10.215.118.1 is: 150 ms, the s.d. is: 5 ms
75 The avg RRT between 192.168.1.12 and 10.216.216.2 is: 200 ms, the s.d. is: 15 ms
76
2
77 4 Deliverables and Marking Scheme
78 For your nal submission of your assignment, you are required to submit your source code to connex.
79 You should include a readme le to tell TA how to compile and run your code. At the last lab
80 session that you attend, you need to demo your assignment to TAs. Nevertheless, before the nal
81 due date, you can still make changes on your code and submit a change.txt le to connex to describe
82 the changes after your demo.
83 The marking scheme is as follows:
Components Weight
Make le 5
The IP address of the source node 5
The IP address of ultimate destination node 5
The IP addresses of the intermediate destination nodes 10
The correct order of the intermediate destination nodes 10
The values in the protocol eld of IP headers 10
The number of fragments created from the original datagram 10
The oset of the last fragment 10
The avg RRTs 15
The standard deviations 10
Code style 5
Readme.txt and change.txt(if any) 5
Total Weight 100
84
85 5 Plagiarism
86 This assignment is to be done individually. You are encouraged to discuss the design of your solution
87 with your classmates, but each person must implement their own assignment.
88 6 Extra Info: Code Quality
89 We cannot specify completely the coding style that we would like to see but it includes the following:
90 1. Proper decomposition of a program into subroutines (and multiple source code les when
91 necessary)|A 500 line program as a single routine won't suce.
92 2. Comment|judiciously, but not profusely. Comments also serve to help a marker, in addition
93 to yourself. To further elaborate:
94 (a) Your favorite quote from StarWars or Douglas Adams' Hitch-hiker's Guide to the Galaxy
95 does not count as comments. In fact, they simply count as anti-comments, and will result
96 in a loss of marks.
97 (b) Comment your code in English. It is the ocial language of this university.
98 3. Proper variable names|leia is not a good variable name, it never was and never will be.
99 4. Small number of global variables, if any. Most programs need a very small number of global
100 variables, if any. (If you have a global variable named temp, think again.)
3
101 5. The return values from all system calls and function calls listed in the assignment
102 specication should be checked and all values should be dealt with appropriately.
103 The End
4





(1) Regarding the output format

"The number of fragments created from the original datagram is:

 The offset of the last fragment is:"



If there are multiple fragmented datagrams, you need to output the above information for each datagram. For example, assume that the source send two datagrams: D1, D2, (where D1 and D2 are the identification of the two datagram) and D1 has three fragments and D2 has two fragments. Then output should be:

"The number of fragments created from the original datagram D1 is: 3

 The offset of the last fragment is: xxx.



"The number of fragments created from the original datagram D2 is: 2

 The offset of the last fragment is: xxx.



(2) It has been found out that in the tracefile captured in Linux, the ID of the original UDP cannot be used to match against the ID field within the data of the returned ICMP error message.  We do not have such a problem in the tracefile captured in Windows.

Currently, I do not have an answer to this strange phenomenon observed in the Linux trace. It seems that the intermediate routes changed the ID value in the IP header of the original UDP, while they are supposed to simply copy the IP header into the ICMP data.  

Nevertheless, the source port number included in the original UDP can be used to match against the ICMP error message. since this is a new finding in linux tracefile, students who do the extra work using UDP source port to match original UDP datagram and ICMP message will get 10% bonus (10% of Assignment 3).



In addition, the student who can first explain the "abnormal" behavior in the linux trace described in (2) will get another 10% bonus (10% of Assignment 3). You need to post your explanation to Connex Chatroom. The first student who finds the right answer (judged by me) gets this 10 % bonus.



Best regards.

 

Kui Wu
