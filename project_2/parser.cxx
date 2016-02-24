/*******************************************************************************
 * @file parser.cxx
 * @author Richard B. Wagner
 * @date 2016-02-23
 * @brief "Limited" TCP trace file parser
 *
 * "The purpose of this project is to learn about the Transmission Control
 * Protocol (TCP). You are required to write a C program with the pcap library
 * to analyze the TCP protocol behavior."
 *
 * @see CSc 361: Computer Communications and Networks (Spring 2016) Assignment 2
 ******************************************************************************/

#include "util.hxx"

#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <cstring>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <netinet/tcp.h>
//#include <time.h>

#include <iostream>
#include <string>
#include <vector>
using namespace std;

struct TCP_hdr {
  u_short	th_sport;		/* source port */
	u_short	th_dport;		/* destination port */
	tcp_seq	th_seq;			/* sequence number */
	tcp_seq	th_ack;			/* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN
	u_char	th_x2:4,		/* (unused) */
		th_off:4;		/* data offset */
#endif
#if BYTE_ORDER == BIG_ENDIAN
	u_char	th_off:4,		/* data offset */
		th_x2:4;		/* (unused) */
#endif
	u_char	th_flags;
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
	u_short	th_win;			/* window */
	u_short	th_sum;			/* checksum */
	u_short	th_urp;			/* urgent pointer */
};

// Global Variable holding the connection(s) state information
vector<Connection *> connections;

void printOutput();

int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y);

int same_connection(struct in_addr ip_a_src, uint16_t port_a_src,
                     struct in_addr ip_a_dst, uint16_t port_a_dst,
                     struct in_addr ip_b_src, uint16_t port_b_src,
                     struct in_addr ip_b_dst, uint16_t port_b_dst) {

  // A little trick to make the one level recursion work
  static bool second_call = false;

  return (  (ip_a_src.s_addr == ip_b_src.s_addr)
         && (ip_a_dst.s_addr == ip_b_dst.s_addr)
         && (port_a_src == port_b_src)
         && (port_a_src == port_b_src) );
         //|| ( (!(second_call = !second_call))
         //&& same_connection(ip_a_src, port_a_src,
         //                   ip_a_dst, port_a_dst,
         //                   ip_b_dst, port_b_dst,
         //                   ip_b_src, port_b_src) );
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);

/**
 *
 */
int main(int argc, char **argv) {
  unsigned int packet_counter = 0;
  struct pcap_pkthdr header;
  const u_char *packet;

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <pcap>\n", argv[0]);
    return (1);
  }

  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  handle = pcap_open_offline(argv[1], errbuf);

  if (handle == NULL) {
    fprintf(stderr, "Couldn't open pcap file %s: %s\n", argv[1], errbuf);
    return (2);
  }

  // pcap_compile (handle, struct bpf_program *fp, char *str, int optimize,
  // bpf_u_int32 netmask)

  pcap_loop(handle, -1, got_packet, NULL);

  printOutput();

  pcap_close(handle);

  return 0;
}

/**
 *
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {

  uint32_t capture_length = header->caplen;
  uint32_t ip_header_length;
  struct ip *ip;
  struct TCP_hdr *tcp;
  bool isNewConnection = false;
  struct timeval tmp_time;
  struct timeval tmp_time_2 = header->ts;
  Connection tmp;

  static struct timeval offset = header->ts;

  if(timeval_subtract(&tmp_time, &tmp_time_2, &offset)==1) {
    offset = tmp_time_2;
  }

  //struct timeval ts; /// time stamp /
  //bpf_u_int32 header.caplen; /// length of portion present /
  //bpf_u_int32 header.len; /// length this packet (off wire) /

  if (capture_length < sizeof(struct ether_header)) {
    exit(1);
  }

  // Skip over the Ethernet header.
  packet += sizeof(struct ether_header);
  capture_length -= sizeof(struct ether_header);

  if (capture_length < sizeof(struct ip)) {exit(1);}

  ip = (struct ip*) packet;
  ip_header_length = ip->ip_hl * 4;	/* ip_hl is in 4-byte words */

  if (capture_length < ip_header_length) {exit(1);}

  // Skip over the IP header.
  packet += ip_header_length;
  capture_length -= ip_header_length;

	tcp = (struct TCP_hdr*) packet;

  // If nothing is in the vector, skip the search step

  //cout << std::to_string(connections.size()) << "sdlkjgnolanhsf";
  if(connections.size()==0) {isNewConnection = true;}

  for (size_t i = 0; !isNewConnection || (i < connections.size()); i++) {
    tmp = *(connections[i]);

    if (same_connection(ip->ip_src, ntohs(tcp->th_sport),
                        ip->ip_dst, ntohs(tcp->th_dport),
                        tmp.sourceAddress, tmp.sourcePort,
                        tmp.destinationAddress, tmp.destinationPort)) {
      isNewConnection = true;
      cout << "true\n";
    }
  }
/*  cout << std::to_string(ip->ip_src.s_addr) << ", "
       << std::to_string(ip->ip_dst.s_addr) << ", "
       << std::to_string(tmp.sourceAddress.s_addr) << ", "
       << std::to_string(tmp.destinationAddress.s_addr) << "\n";*/
  if (isNewConnection) {
    cout << "NEW CON";
    usleep(10000);
    Connection new_connection;
    new_connection.sourceAddress->s_addr = ip->ip_src.s_addr;
    new_connection.destinationAddress->s_addr = ip->ip_dst.s_addr;
    new_connection.sourcePort = ntohs(tcp->th_sport);
    new_connection.destinationPort = ntohs(tcp->th_dport);
    connections.push_back(&new_connection);
    cout << std::to_string(new_connection.destinationAddress.s_addr) << "\n";
  }


}

/**
 * Prints the statistics from the TCP trace file parser to the screen
 */
void printOutput() {
  std::string result = "";
  std::size_t n = connections.size();

  result += "\nA) Total number of connections: " + std::to_string(42);

  result += "\n----------------------------------------------------------------"
            "----------------\n";

  result += "\nB) Connections' details:\n";

  // for (std::vector<int>::iterator it = fifth.begin(); it != fifth.end();
  // ++it)
  for (std::size_t i = 0; i < n; i++) {
    result += "\n\tConnection " + std::to_string(i) + ":";
    result += "\n\t          Source Address:";
    result += "\n\t     Destination address:";
    result += "\n\t             Source Port:";
    result += "\n\tDestination Port: Status:";

    // (Only if the connection is complete provide the following information)
    // Start time:
    result += "\n\t                                       End Time:";
    result += "\n\t                                       Duration:";
    result += "\n\t   # of packets sent from Source to Destination:";
    result += "\n\t   # of packets sent from Destination to Source:";
    result += "\n\t                        Total number of packets:";
    result += "\n\t# of data bytes sent from Source to Destination:";
    result += "\n\t# of data bytes sent from Destination to Source:";
    result += "\n\t                     Total number of data bytes:";
    result += "\n\tEND";

    if (n - i > 1)
      result +=
          "\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
          "++++++++++++++";
  }

  result += "\n----------------------------------------------------------------"
            "----------------\n";

  result += "\nC) General\n";
  result += "\nTotal number of complete TCP connections:";
  result += "\nNumber of reset TCP connections:";
  result += "\nNumber of TCP connections that were still open when the trace "
            "capture ended:";

  result += "\n----------------------------------------------------------------"
            "----------------\n";

  result += "\nD) Complete TCP connections:\n";
  result += "\nMinimum time durations: ";
  result += "\nMean time durations: ";
  result += "\nMaximum time durations:";

  result += "\nMinimum RTT values including both send/received: ";
  result += "\nMean RTT values including both send/received: ";
  result += "\nMaximum RTT values including both send/received:";

  result += "\nMinimum number of packets including both send/received: ";
  result += "\nMean number of packets including both send/received: ";
  result += "\nMaximum number of packets including both send/received:";

  result += "\nMinimum receive window sizes including both send/received: ";
  result += "\nMean receive window sizes including both send/received: ";
  result += "\nMaximum receive window sizes including both send/received:";

  //std::cout << result;
}

/* Subtract the ‘struct timeval’ values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0. */

int
timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y)
{
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}
