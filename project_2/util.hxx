/*******************************************************************************
 * @file util.hxx
 * @author Richard B. Wagner
 * @date 2016-02-27
 * @brief "Limited" TCP trace file parser
 *
 * "The purpose of this project is to learn about the Transmission Control
 * Protocol (TCP). You are required to write a C program with the pcap library
 * to analyze the TCP protocol behavior."
 *
 * @see CSc 361: Computer Communications and Networks (Spring 2016) Assignment 2
 ******************************************************************************/

#ifndef _UTIL_HXX
#define _UTIL_HXX

//#include <stdio.h>
//#include <unistd.h>
//#include <netinet/in.h>

//#include <net/if.h>

#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <pcap.h>

/******************************************************************************/
//#include <sys/time.h>
#include <stdlib.h>
#include <assert.h>
/******************************************************************************/

//#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/tcp.h>

#include <cstring>
#include <iostream>
//#include <string>
//#include <cstdio>
#include <functional>
#include <vector>
//#include <ctime>
//#include <cstdint>

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

struct Packet {
  const struct pcap_pkthdr *header;
  const u_char *packet;
};

struct Status {
  u_int8_t syn;
  u_int8_t fin;
  u_int8_t rst;
};
#define _timercmp(a, b, CMP)                                                    \
  (((a).tv_sec == (b).tv_sec) ? ((a).tv_usec CMP(b).tv_usec)                   \
                              : ((a).tv_sec CMP(b).tv_sec))

const char *timestamp_string(struct timeval ts);

std::string timeval_subtract(struct timeval x, struct timeval y);

bool is_header_intact(const struct pcap_pkthdr *header, const u_char *packet);

int timeval_subtract(struct timeval *result, struct timeval x,
                     struct timeval y);

int timeval_subtract(struct timeval *result, struct timeval *x,
                     struct timeval *y);

struct ether_header *get_ether_header(const u_char *packet);

struct ip *get_ip_header(const u_char *packet);

struct TCP_hdr *get_tcp_header(const u_char *packet);

const u_char *get_payload(const struct pcap_pkthdr *header,
                          const u_char *packet);

uint64_t get_payload_size(const struct pcap_pkthdr *header,
                          const u_char *packet);

std::string status_to_string(Status status);

class Connection {
public:         // begin public section
  Connection(); // constructor

  Connection(const struct pcap_pkthdr *header, const u_char *packet);

  // Connection(const Connection &copy_from); // copy constructor

  // Connection &operator=(const Connection &copy_from); // copy assignment

  ~Connection(); // destructor

  struct in_addr get_source_address() const;
  struct in_addr get_destination_address() const;
  uint16_t get_source_port() const;
  uint16_t get_destination_port() const;

  struct timeval get_end_time() const;

  bool get_duration(struct timeval *result) const;

  uint32_t get_number_packets_source_to_destination() const;
  uint32_t get_number_packets_destination_to_source() const;
  uint64_t get_number_bytes_source_to_destination() const;
  uint64_t get_number_bytes_destination_to_source() const;

  void add_packet(const u_char *packet, const struct pcap_pkthdr *header);
  uint32_t get_number_packets() const;
  uint64_t get_number_bytes() const;

  struct timeval get_duration() const;

  struct Status get_status();

  struct timeval get_rtt();

  std::vector<struct timeval> get_rtt_list();

  std::vector<const u_char *> packets;
  std::vector<const struct pcap_pkthdr *> pcap_packet_headers;

protected:
private:
};

/** A function that tests if two Connection objects have the same source and
 * destination addresses/ports.
 *
 * @param {Connection *} a the first connection
 * @param {Connection *} b the second connection
 * @param {bool} mirror the flag that specifies whether to return true if the
 * source and destination addresses/ports can be reversed
 */
bool is_same_connection(Connection *a, Connection *b, bool mirror);

bool is_same_connection(Connection *a, Connection *b);

uint64_t avg(std::vector<Connection> *vec,
                std::function<uint64_t(Connection)> f);

uint64_t max(std::vector<Connection> *vec,
                std::function<uint64_t(Connection)> f);

uint64_t min(std::vector<Connection> *vec,
                std::function<uint64_t(Connection)> f);

struct timeval get_relative_time(std::vector<Connection> connections);

#endif

// struct timeval ts; /// time stamp /
// bpf_u_int32 header.caplen; /// length of portion present /
// bpf_u_int32 header.len; /// length this packet (off wire) /

/*


for (size_t i=0;(i < connections.size()); i++) {
  tmp = connections.at(i);


  isNewConnection = ! same_connection(ip->ip_src, ntohs(tcp->th_sport),
                      ip->ip_dst, ntohs(tcp->th_dport),
                      tmp.sourceAddress, tmp.sourcePort,
                      tmp.destinationAddress, tmp.destinationPort);
}


*/
