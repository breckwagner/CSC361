/*******************************************************************************
 * @file util.cxx
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

Connection::Connection() {}

Connection::Connection(const struct pcap_pkthdr *header, const u_char *packet) {
  // TODO TEST if it is a valid connection and fail gracefully
  try {
    this->pcap_packet_headers.emplace_back(header);
    this->packets.emplace_back(packet);
  } catch (std::exception &e) {
    std::cerr << "Exception catched : " << e.what() << std::endl;
  }
}

Connection::~Connection() {}

struct in_addr Connection::get_source_address() {
  return get_ip_header(packets.front())->ip_src;
}
struct in_addr Connection::get_destination_address() {
  return get_ip_header(packets.front())->ip_dst;
}
uint16_t Connection::get_source_port() {
  return ntohs(get_tcp_header(packets.front())->th_sport);
}

uint16_t Connection::get_destination_port() {
  return ntohs(get_tcp_header(packets.front())->th_dport);
}

struct timeval Connection::get_end_time() {
  return pcap_packet_headers.back()->ts;
}

bool Connection::get_duration(struct timeval *result) {
  return (bool)timeval_subtract(result, pcap_packet_headers.back()->ts,
                                pcap_packet_headers.front()->ts);
}

struct timeval Connection::get_duration() {
  struct timeval result;
  timeval_subtract(&result, pcap_packet_headers.back()->ts,
                   pcap_packet_headers.front()->ts);
  return result;
}

struct timeval Connection::get_rtt() {
  struct timeval result;
  std::vector<struct Packet *> single;

  // TODO
  // uint32_t th_seq;
  // uint32_t th_ack;
  for (size_t n = 0; n < packets.size(); n++) {

    std::cout << get_tcp_header(packets.at(n))->th_seq;
    // auto x = (struct Packet *){pcap_packet_headers.at(n), packets.at(n)};
    // single.push_back(x);
  }
  // timeval_subtract(&result, pcap_packet_headers.back()->ts,
  //                 pcap_packet_headers.front()->ts);
  return result;
}

uint32_t Connection::get_number_packets_source_to_destination() {
  size_t n = 0;
  for (size_t i = 0; i < packets.size(); i++) {
    if (get_source_address().s_addr == get_ip_header(packets.at(i))->ip_src.s_addr)
      n++;
  }
  return n;
}
uint32_t Connection::get_number_packets_destination_to_source() {
  size_t n = 0;
  for (size_t i = 0; i < packets.size(); i++) {
    if (get_source_address().s_addr !=
        get_ip_header(packets.at(i))->ip_src.s_addr) {
      n++;
    }
  }
  return n;
}
uint64_t Connection::get_number_bytes_source_to_destination() {
  uint64_t n = 0;
  for (size_t i = 0; i < packets.size(); i++) {
    if (get_source_address().s_addr == get_ip_header(packets.at(i))->ip_src.s_addr)
      n += pcap_packet_headers.at(i)->caplen;
  }
  return n;
}
uint64_t Connection::get_number_bytes_destination_to_source() {
  uint64_t n = 0;
  for (size_t i = 0; i < packets.size(); i++) {
    if (get_source_address().s_addr != get_ip_header(packets.at(i))->ip_src.s_addr)
      n += pcap_packet_headers.at(i)->caplen;
  }
  return n;
}

void Connection::add_packet(const u_char *packet,
                            const struct pcap_pkthdr *header) {
  this->pcap_packet_headers.emplace_back(header);
  this->packets.emplace_back(packet);
}

uint32_t Connection::get_number_packets() {
  return get_number_packets_source_to_destination() +
         get_number_packets_destination_to_source();
}

uint64_t Connection::get_number_bytes() {
  return get_number_bytes_source_to_destination() +
         get_number_bytes_destination_to_source();
}

// TODO
uint64_t Connection::get_window() {
  uint64_t n = 0, j = 0;
  for (size_t i = 0; i < packets.size(); i++) {
    if (get_source_address().s_addr != get_ip_header(packets.at(i))->ip_src.s_addr) {
      n += get_tcp_header(packets.at(i))->th_win;
      j++;
    }
  }
  return n/j;
}

std::string status_to_string(Status status) {
  if (status.rst > 0) return "R";
  else return "s" + std::to_string(status.syn) + "f" + std::to_string(status.fin);
}

struct Status Connection::get_status() {
  struct Status status = (struct Status){0,0,0};
  for (const u_char *p : packets) {
    if (get_tcp_header(p)->th_flags & TH_FIN) ++(status.fin);
    if (get_tcp_header(p)->th_flags & TH_SYN) ++(status.syn);
    if (get_tcp_header(p)->th_flags & TH_RST) ++status.rst;
  }
  return status;
}

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
  struct timeval result = (struct timeval){x.tv_sec - y.tv_sec, x.tv_usec - y.tv_usec};
  if (result.tv_usec < 0) {
    --(result.tv_sec);
    (result.tv_usec) += 1000000;
  }
  return timestamp_string(result);
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

bool is_same_connection(Connection *a, Connection *b, bool mirror) {
  return _is_same_connection(a->get_source_address(), a->get_source_port(),
                             a->get_destination_address(),
                             a->get_destination_port(), b->get_source_address(),
                             b->get_source_port(), b->get_destination_address(),
                             b->get_destination_port(), mirror);
}
bool is_same_connection(Connection *a, Connection *b) {
  return is_same_connection(a, b, true);
}

/**
 * @param {vector<Conection>}
 * @param {std::function}
 * function f should be of the format:
 * [](Connection * c) {return c.%parameter%}
 */
uint64_t avg(std::vector<Connection> *vec,
                std::function<uint64_t(Connection)> f) {
  uint64_t value = f(vec->front());
  for (Connection i : *vec)
    value += f(i);
  return value / ((double)vec->size());
}

/**
 * @param {vector<Conection>}
 * @param {std::function}
 * function f should be of the format:
 * [](Connection * c) {return c.%parameter%}
 */
uint64_t max(std::vector<Connection> *vec,
                std::function<uint64_t(Connection)> f) {
  uint64_t value = f(vec->front());
  for (Connection i : *vec)
    if (value < f(i))
      value = f(i);
  return value;
}

/**
 * @param {vector<Conection>}
 * @param {std::function}
 * function f should be of the format:
 * [](Connection * c) {return c.%parameter%}
 */
uint64_t min(std::vector<Connection> *vec,
                std::function<uint64_t(Connection)> f) {
  uint64_t value = f(vec->front());
  for (Connection i : *vec)
    if (value > f(i))
      value = f(i);
  return value;
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

const u_char * get_payload(const struct pcap_pkthdr *header, const u_char *packet) {
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

struct timeval get_relative_time(std::vector<Connection> connections) {
  struct timeval offset = connections.front().pcap_packet_headers.front()->ts;
  return offset;
}
