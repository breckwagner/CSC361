

#ifndef _UTIL_HXX
#define _UTIL_HXX

#include <netinet/ip.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <pcap.h>


#include <sys/socket.h>
#include <arpa/inet.h>

#include <netinet/tcp.h>

#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <ctime>
#include <cstdint>

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



const char *timestamp_string(struct timeval ts);

int timeval_subtract(struct timeval *result, struct timeval *x,
                     struct timeval *y);


class Connection {
public:                       // begin public section
  Connection(); // constructor

  Connection(struct ip *ip, struct TCP_hdr *tcp);
  //Connection(const Connection &copy_from); // copy constructor
  //Connection &operator=(const Connection &copy_from); // copy assignment
  ~Connection(); // destructor

  struct in_addr sourceAddress;
  struct in_addr destinationAddress;
  uint16_t sourcePort;
  uint16_t destinationPort;
  struct timeval endTime;
  struct timeval duration;

  uint32_t numberPacketsSourceToDestination;
  uint32_t numberPacketsDestinationToSource;

  uint64_t numberBytesSourceToDestination;
  uint64_t numberBytesDestinationToSource;


  void set_source_address(struct in_addr new_address);
  void set_destination_address(struct in_addr new_address);
  void set_source_port(uint16_t new_port);
  void set_destination_port(uint16_t new_port);
  void set_end_time(struct timeval new_time);
  void set_duration(struct timeval new_duration);
  void set_number_packets_source_to_destination(uint32_t new_value);
  void set_number_packets_destination_to_source(uint32_t new_value);
  void set_number_bytes_source_to_destination(uint64_t new_value);
  void set_number_bytes_destination_to_source(uint64_t new_value);

  struct in_addr get_source_address();
  struct in_addr get_destination_address();
  uint16_t get_source_port();
  uint16_t get_destination_port();
  struct timeval get_end_time();
  struct timeval get_duration();
  uint32_t get_number_packets_source_to_destination();
  uint32_t get_number_packets_destination_to_source();
  uint64_t get_number_bytes_source_to_destination();
  uint64_t get_number_bytes_destination_to_source();

  void add_packet(struct ip *ip, struct TCP_hdr *tcp);
  uint32_t get_number_packets();
  uint64_t get_number_bytes();

private:
  std::vector<struct ip *> ip_packet_headers;
  std::vector<struct TCP_hdr *> tcp_packet_headers;

};

int is_same_connection(struct ip *ip, struct TCP_hdr *tcp, Connection *connection);

/** A function that tests if two Connection objects have the same source and
 * destination addresses/ports.
 *
 * @param {Connection *} a the first connection
 * @param {Connection *} b the second connection
 * @param {bool} mirror the flag that specifies whether to return true if the
 * source and destination addresses/ports can be reversed
 */
bool is_same_connection(Connection * a, Connection * b, bool mirror);

bool is_same_connection(Connection * a, Connection * b);

#endif


//struct timeval ts; /// time stamp /
//bpf_u_int32 header.caplen; /// length of portion present /
//bpf_u_int32 header.len; /// length this packet (off wire) /



/*


for (size_t i=0;(i < connections.size()); i++) {
  tmp = connections.at(i);


  isNewConnection = ! same_connection(ip->ip_src, ntohs(tcp->th_sport),
                      ip->ip_dst, ntohs(tcp->th_dport),
                      tmp.sourceAddress, tmp.sourcePort,
                      tmp.destinationAddress, tmp.destinationPort);
}


*/
