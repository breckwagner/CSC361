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
  u_short th_sport;
  u_short th_dport;
  tcp_seq th_seq;
  tcp_seq th_ack;
#if BYTE_ORDER == LITTLE_ENDIAN
  u_char th_x2 : 4, th_off : 4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
  u_char th_off : 4, th_x2 : 4;
#endif
  u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
  u_short th_win;
  u_short th_sum;
  u_short th_urp;
};

// Global Variable holding the connection(s) state information
std::vector<Connection> connections;

void printOutput();

int same_connection(struct in_addr ip_a_src, uint16_t port_a_src,
                    struct in_addr ip_a_dst, uint16_t port_a_dst,
                    struct in_addr ip_b_src, uint16_t port_b_src,
                    struct in_addr ip_b_dst, uint16_t port_b_dst);

int same_connection(struct ip * ip, struct TCP_hdr * tcp,
                    Connection * connection) {
  return same_connection(ip->ip_src, ntohs(tcp->th_sport), ip->ip_dst,
    ntohs(tcp->th_dport),
    connection->get_source_address(),
    connection->get_source_port(),
    connection->get_destination_address(),
    connection->get_destination_port());
}

int same_connection(struct in_addr ip_a_src, uint16_t port_a_src,
                    struct in_addr ip_a_dst, uint16_t port_a_dst,
                    struct in_addr ip_b_src, uint16_t port_b_src,
                    struct in_addr ip_b_dst, uint16_t port_b_dst) {

  // A little trick to make the one level recursion work
  static bool second_call = false;

  return ((ip_a_src.s_addr == ip_b_src.s_addr) &&
          (ip_a_dst.s_addr == ip_b_dst.s_addr) && (port_a_src == port_b_src) &&
          (port_a_dst == port_b_dst)) ||
         ((!(second_call = !second_call)) &&
          same_connection(ip_a_src, port_a_src, ip_a_dst, port_a_dst, ip_b_dst,
                          port_b_dst, ip_b_src, port_b_src));
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
  struct bpf_program fp;      /* hold compiled program     */
  bpf_u_int32 maskp;          /* subnet mask               */
  bpf_u_int32 netp;           /* ip                        */

  if (argc < 2) {
    cerr << "Usage: " << argv[0] << "<pcap>\n";
    return EXIT_FAILURE;
  }

  pcap_t *descr;
  char errbuf[PCAP_ERRBUF_SIZE];
  descr = pcap_open_offline(argv[1], errbuf);

  if (descr == NULL) {
    cerr << "Couldn't open pcap file" << argv[1] << ": " << errbuf << "\n";
    return EXIT_FAILURE;
  }

  /* Lets try and compile the program.. non-optimized */
  if (pcap_compile(descr, &fp, "tcp", 0, netp) == -1) {
    cerr << "Error calling pcap_compile\n";
    return EXIT_FAILURE;
  }

  /* set the compiled program as the filter */
  if (pcap_setfilter(descr, &fp) == -1) {
    cerr << "Error setting filter\n";
    return EXIT_FAILURE;
  }

  pcap_loop(descr, -1, got_packet, NULL);

  printOutput();

  pcap_close(descr);

  return EXIT_SUCCESS;
}

/**
 *
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
  static uint64_t count = 0;
  uint32_t capture_length = header->caplen;
  uint32_t ip_header_length;
  struct ip *ip;
  struct TCP_hdr *tcp;
  bool isNewConnection = true;
  struct timeval tmp_time;
  struct timeval tmp_time_2 = header->ts;

  static struct timeval offset = header->ts;

  if (timeval_subtract(&tmp_time, &tmp_time_2, &offset) == 1) {
    offset = tmp_time_2;
  }

  if (capture_length < sizeof(struct ether_header)) {
    return;
  }

  // Skip over the Ethernet header.
  packet += sizeof(struct ether_header);
  capture_length -= sizeof(struct ether_header);

  if (capture_length < sizeof(struct ip)) {
    return;
  }

  ip = (struct ip *)packet;
  ip_header_length = ip->ip_hl * 4; /* ip_hl is in 4-byte words */

  if (capture_length < ip_header_length) {
    return;
  }

  // Skip over the IP header.
  packet += ip_header_length;
  capture_length -= ip_header_length;

  tcp = (struct TCP_hdr *)packet;

  for (Connection &tmp : connections) {
    if (same_connection(ip, tcp, &tmp)) {
      isNewConnection = false;
      break;
    }
  }

  if (isNewConnection) {
    Connection new_connection;
    new_connection.set_source_address(ip->ip_src);
    new_connection.set_destination_address(ip->ip_dst);
    new_connection.set_source_port(ntohs(tcp->th_sport));
    new_connection.set_destination_port(ntohs(tcp->th_dport));
    connections.emplace_back(new_connection);
    cout << inet_ntoa(new_connection.get_source_address()) << ":"
         << std::to_string(new_connection.get_source_port()) << ", "
         << inet_ntoa(new_connection.get_destination_address()) << ":"
         << std::to_string(new_connection.get_destination_port()) << "|"
         << std::to_string(connections.size()) << "|\n";
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

  // std::cout << result;
}
