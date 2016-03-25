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
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <pcap.h>

/*
RTT use sequance number to match packets

Message fragmentation flag in ICMP is MF=1

fragmet count every packet that is fragmented

offset of last fragment
*/

#include <cstring>
#include <iostream>
#include <functional>
#include <vector>
#include <map>
#include <cstdlib>
#include <algorithm>
//#include <cmath>
//#include <string>
//#include <cstdio>
//#include <ctime>
//#include <cstdint>

/*

struct pcap_pkthdr {
  struct timeval ts;
  bpf_u_int32 caplen;
  bpf_u_int32 len;
};

*/

enum PROTOCOL_TYPE : uint8_t {
  HOPOPT = 0,
  ICMP,
  IGMP,
  GGP,
  IPV4,
  ST,
  TCP,
  CBT,
  EGP,
  IGP,
  BBN_RCC_MON,
  NVP_II,
  PUP,
  ARGUS, /**< @deprecated */
  EMCON,
  XNET,
  CHAOS,
  UDP,
  MUX,
  DCN_MEAS,
  HMP,
  PRM,
  XNS_IDP/*,
  TRUNK-1,
  TRUNK-2,
  LEAF-1,
  LEAF-2,
  RDP,
  IRTP,
  ISO-TP4,
  NETBLT,
  MFE-NSP,
  MERIT-INP,
  DCCP,
  3PC,
  IDPR,
  XTP,
  DDP,
  IDPR-CMTP,
  TP++,
  IL,
  IPV6,
  SDRP,
  IPV6-ROUTE,
  IPV6-FRAG,
  IDRP,
  RSVP,
  GRE,
  DSR,
  BNA,
  ESP,
  AH,
  I-NLSP,
  SWIPE (DEPRECATED),
  NARP,
  MOBILE,
  TLSP,
  SKIP,
  IPV6-ICMP,
  IPV6-NONXT,
  IPV6-OPTS,
  ,
  CFTP,
  ,
  SAT-EXPAK,
  KRYPTOLAN,
  RVD,
  IPPC,
  ,
  SAT-MON,
  VISA,
  IPCV,
  CPNX,
  CPHB,
  WSN,
  PVP,
  BR-SAT-MON,
  SUN-ND,
  WB-MON,
  WB-EXPAK,
  ISO-IP,
  VMTP,
  SECURE-VMTP,
  VINES,
  TTP,
  IPTM,
  NSFNET-IGP,
  DGP,
  TCF,
  EIGRP,
  OSPFIGP,
  SPRITE-RPC,
  LARP,
  MTP,
  AX.25,
  IPIP,
  MICP (DEPRECATED),
  SCC-SP,
  ETHERIP,
  ENCAP,
  ,
  GMTP,
  IFMP,
  PNNI,
  PIM,
  ARIS,
  SCPS,
  QNX,
  A/N,
  IPCOMP,
  SNP,
  COMPAQ-PEER,
  IPX-IN-IP,
  VRRP,
  PGM,
  L2TP = 115,
  DDX,
  IATP,
  STP,
  SRP,
  UTI,
  SMP,
  SM,
  PTP,
  ISIS OVER IPV4,
  FIRE,
  CRTP,
  CRUDP,
  SSCOPMCE,
  IPLT,
  SPS,
  PIPE,
  SCTP,
  FC,
  RSVP-E2E-IGNORE,
  MOBILITY HEADER,
  UDPLITE,
  MPLS-IN-IP,
  MANET,
  HIP,
  SHIM6,
  WESP,
  ROHC*/
};

enum class ICMP_TYPE {
  ECHO_REPLY = 0,
  DESTINATION_UNREACHABLE = 3,
  SOURCE_QUENCH,
  REDIRECT,
  ALTERNATE_HOST_ADDRESS,
  ECHO = 8,
  ROUTER_ADVERTISEMENT,
  ROUTER_SOLICITATION,
  TIME_EXCEEDED,
  PARAMETER_PROBLEM,
  TIMESTAMP,
  TIMESTAMP_REPLY,
  INFORMATION_REQUEST,
  INFORMATION_REPLY,
  ADDRESS_MASK_REQUEST,
  ADDRESS_MASK_REPLY,
  TRACEROUTE = 30,
  DATAGRAM_CONVERSION_ERROR,
  MOBILE_HOST_REDIRECT,
  IPV6_WHERE_ARE_YOU,
  IPV6_I_AM_HERE,
  MOBILE_REGISTRATION_REQUEST,
  MOBILE_REGISTRATION_REPLY,
  DOMAIN_NAME_REQUEST,
  DOMAIN_NAME_REPLY,
  SKIP,
  PHOTURIS
};


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

struct udphdr *get_udp_header(const u_char *packet);

const u_char *get_payload(const struct pcap_pkthdr *header,
                          const u_char *packet);

uint64_t get_payload_size(const struct pcap_pkthdr *header,
                          const u_char *packet);

bool is_header_intact(const struct pcap_pkthdr *header, const u_char *packet);

std::string get_protocal(uint8_t protocol_number);

#endif
