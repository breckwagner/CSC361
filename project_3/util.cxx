/*******************************************************************************
 * @file util.cxx
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

#include "util.hxx"


/* Note, this routine returns a pointer into a static buffer, and
 * so each call overwrites the value returned by the previous call.
 */
const char *timestamp_string(struct timeval ts) {
  static char timestamp_string_buf[256];

  sprintf(timestamp_string_buf, "%6d.%06d", (int)ts.tv_sec, (int)ts.tv_usec);

  return timestamp_string_buf;
}

/* Subtract the ‘struct timeval’ values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0. */

int timeval_subtract(struct timeval *result, struct timeval *x,
                     struct timeval *y) {
  *result = (struct timeval){x->tv_sec - y->tv_sec, x->tv_usec - y->tv_usec};
  if (result->tv_usec < 0) {
    --(result->tv_sec);
    (result->tv_usec) += 1000000;
    return 1;
  } else {
    return 0;
  }
}
int timeval_subtract(struct timeval *result, struct timeval x,
                     struct timeval y) {
  *result = (struct timeval){x.tv_sec - y.tv_sec, x.tv_usec - y.tv_usec};
  if (result->tv_usec < 0) {
    --(result->tv_sec);
    (result->tv_usec) += 1000000;
    return 1;
  } else {
    return 0;
  }
}

std::string timeval_subtract(struct timeval x, struct timeval y) {
  struct timeval result =
      (struct timeval){x.tv_sec - y.tv_sec, x.tv_usec - y.tv_usec};
  if (result.tv_usec < 0) {
    --(result.tv_sec);
    (result.tv_usec) += 1000000;
  }
  return timestamp_string(result);
}

/**
 * @param {const u_char *} packet
 * @return {struct ether_header *}
 */
struct ether_header *get_ether_header(const u_char *packet) {
  return (struct ether_header *)packet;
}

/**
 * @param {const u_char *} packet
 * @return {struct ip *}
 */
struct ip *get_ip_header(const u_char *packet) {
  const u_char *pointer = packet + sizeof(struct ether_header);
  return (struct ip *)pointer;
}

/**
 * @param {const u_char *} packet
 * @return {struct TCP_hdr *}
 */
struct TCP_hdr *get_tcp_header(const u_char *packet) {
  const u_char *pointer =
      packet + sizeof(struct ether_header) + (get_ip_header(packet)->ip_hl * 4);
  return (struct TCP_hdr *)pointer;
}

const u_char *get_payload(const struct pcap_pkthdr *header,
                          const u_char *packet) {
  if (!is_header_intact(header, packet))
    throw std::out_of_range("The packet is corrupted or has no payload");
  const u_char *pointer = packet + sizeof(struct ether_header) +
                          (get_ip_header(packet)->ip_hl * 4) +
                          get_tcp_header(packet)->th_off * 4;
  return pointer;
}

uint64_t get_payload_size(const struct pcap_pkthdr *header,
                          const u_char *packet) {
  uint64_t offset = sizeof(struct ether_header) +
                    get_ip_header(packet)->ip_hl * 4 +
                    get_tcp_header(packet)->th_off * 4;

  return header->caplen - offset;
}

bool is_header_intact(const struct pcap_pkthdr *header, const u_char *packet) {
  uint64_t pointer_offset = 0;
  uint64_t len = header->caplen;

  if(len < sizeof(struct ether_header)) return false;
  pointer_offset += sizeof(struct ether_header);

  if(len < pointer_offset + sizeof(struct ip)) return false;
  pointer_offset += (get_ip_header(packet)->ip_hl * 4);

  if(len < pointer_offset + sizeof(struct TCP_hdr)) return false;
  pointer_offset += get_tcp_header(packet)->th_off * 4;

  return (len >= pointer_offset);
}

std::string get_protocal(uint8_t protocol_number) {
  switch(protocol_number) {
    case 1: return "ICMP";
    case 6: return "TCP";
    case 17: return "UDP";
    default: return "Undefined";
  }
}

int _is_same_connection(struct in_addr ip_a_src, uint16_t port_a_src,
                        struct in_addr ip_a_dst, uint16_t port_a_dst,
                        struct in_addr ip_b_src, uint16_t port_b_src,
                        struct in_addr ip_b_dst, uint16_t port_b_dst,
                        bool recursion) {
  return ((ip_a_src.s_addr == ip_b_src.s_addr) &&
          (ip_a_dst.s_addr == ip_b_dst.s_addr) && (port_a_src == port_b_src) &&
          (port_a_dst == port_b_dst)) ||
         (recursion && _is_same_connection(ip_a_src, port_a_src, ip_a_dst,
                                           port_a_dst, ip_b_dst, port_b_dst,
                                           ip_b_src, port_b_src, false));
}
