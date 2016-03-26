# CSc 361: Computer Communications and Networks (Spring 2016)
## Assignment 3 - README

https://courses1.csc.uvic.ca/courses/2016/spring/csc/361

### Requirements
pcap library: libpcap, libpcap-dev

### Assumptions
For the purpose of simplifying the problem, we will assume that
  - two traceroute commands will not overlap in the packet stream if they have
    the same ip.dst and ip.src
  - the traceroute will use all standard flags with the exception of the
    UDP/ICMP select flag
  - I assume that there will only by UDP, ICMP and TCP packets (for the most   
    part). If other protocols are captured, they will by counted in the Header
    Protocol section but will be listed as unknown.
  - There are other assumptions made which have been documented in my code with
    "NOTE: ..." statements.

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
