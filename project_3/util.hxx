/*******************************************************************************
 * @file util.hxx
 * @author Richard B. Wagner
 * @date 2016-03-25
 * @brief "Limited" IP traceroute file parser
 *
 * "The purpose of this project is to learn about the IP protocol. You are
 * required to write a C program with the pcap library to analyze a trace of IP
 * datagrams."
 *
 * @see CSc 361: Computer Communications and Networks (Spring 2016) Assignment 3
 ******************************************************************************/

#ifndef _UTIL_HXX
#define _UTIL_HXX

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <pcap.h>

#include <cstring>
#include <iostream>
#include <functional>
#include <vector>
#include <cstdlib>
#include <algorithm>
//#include <cmath>
//#include <string>
//#include <cstdio>
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

typedef struct {
  const struct pcap_pkthdr *header;
  const u_char *packet;
} Packet;

typedef struct {
  std::vector<Packet> request_packets;
  std::vector<Packet> response_packets;
} Hop;

const char *timestamp_string(struct timeval ts);

int timeval_subtract(struct timeval *result, struct timeval *x,
                     struct timeval *y);

int timeval_subtract(struct timeval *result, struct timeval x,
                     struct timeval y);

std::string timeval_subtract(struct timeval x, struct timeval y);

struct ether_header *get_ether_header(const u_char *packet);

struct ip *get_ip_header(const u_char *packet);

struct TCP_hdr *get_tcp_header(const u_char *packet);

const u_char *get_payload(const struct pcap_pkthdr *header,
                          const u_char *packet);

uint64_t get_payload_size(const struct pcap_pkthdr *header,
                          const u_char *packet);

bool is_header_intact(const struct pcap_pkthdr *header, const u_char *packet);

std::string get_protocal(uint8_t protocol_number);

#endif
