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

Connection::Connection(struct ip *ip, struct TCP_hdr *tcp) {
  set_source_address(ip->ip_src);
  set_destination_address(ip->ip_dst);
  set_source_port(ntohs(tcp->th_sport));
  set_destination_port(ntohs(tcp->th_dport));
  ip_packet_headers.emplace_back(ip);
  tcp_packet_headers.emplace_back(tcp);
}

Connection::Connection(struct ip *ip, struct TCP_hdr *tcp, struct pcap_pkthdr * pcap) {
  set_source_address(ip->ip_src);
  set_destination_address(ip->ip_dst);
  set_source_port(ntohs(tcp->th_sport));
  set_destination_port(ntohs(tcp->th_dport));
  ip_packet_headers.emplace_back(ip);
  tcp_packet_headers.emplace_back(tcp);
  pcap_packet_headers.emplace_back(pcap);
}

Connection::~Connection() {}

void Connection::set_source_address(struct in_addr new_value) {
  this->sourceAddress = new_value;
}
void Connection::set_destination_address(struct in_addr new_value) {
  this->destinationAddress = new_value;
}
void Connection::set_source_port(uint16_t new_value) {
  this->sourcePort = new_value;
}
void Connection::set_destination_port(uint16_t new_value) {
  this->destinationPort = new_value;
}
void Connection::set_end_time(struct timeval new_value) {
  this->endTime = new_value;
}
void Connection::set_duration(struct timeval new_value) {
  this->duration = new_value;
}
void Connection::set_number_packets_source_to_destination(uint32_t new_value) {
  this->numberPacketsSourceToDestination = new_value;
}
void Connection::set_number_packets_destination_to_source(uint32_t new_value) {
  this->numberPacketsDestinationToSource = new_value;
}
void Connection::set_number_bytes_source_to_destination(uint64_t new_value) {
  this->numberBytesSourceToDestination = new_value;
}
void Connection::set_number_bytes_destination_to_source(uint64_t new_value) {
  this->numberBytesDestinationToSource = new_value;
}

struct in_addr Connection::get_source_address() {
  return this->sourceAddress;
}
struct in_addr Connection::get_destination_address() {
  return this->destinationAddress;
}
uint16_t Connection::get_source_port() { return this->sourcePort; }

uint16_t Connection::get_destination_port() { return this->destinationPort; }

struct timeval Connection::get_end_time() {
  /*
  struct timeval * result;
  struct timeval * max = &(pcap_packet_headers.front()->ts);
  for (struct pcap_pkthdr * i : pcap_packet_headers) {
    if(timeval_subtract(result, max, &(i->ts))==1) max = &(i->ts);
  }
  return *max;
  */
  return timeval_of_packets.back();
}

bool Connection::get_duration(struct timeval * result) {
  //timestamp_string((struct timeval) {i.timeval_of_packets.back().tv_sec-i.timeval_of_packets.front().tv_sec, i.timeval_of_packets.back().tv_usec-i.timeval_of_packets.front().tv_usec})
  //struct timeval * min = &(pcap_packet_headers.front()->ts);
  //struct timeval * max = &(pcap_packet_headers.front()->ts);
  //struct timeval min = timeval_of_packets.front();
  //struct timeval max;
  //timeval_subtract(result, &max, &min);
  /*for (struct pcap_pkthdr * i : pcap_packet_headers) {
    if(timeval_subtract(result, &(i->ts), min)==1) min = &(i->ts);
    if(timeval_subtract(result, max, &(i->ts))==1) max = &(i->ts);
  }*/
  //return (bool) timeval_subtract(result, max, min);
  return true;
}

struct timeval Connection::get_duration() {
  time_t tv_sec_a = timeval_of_packets.front().tv_sec;
  uint32_t tv_usec_a = timeval_of_packets.front().tv_usec;
  time_t tv_sec_b = timeval_of_packets.back().tv_sec;
  uint32_t tv_usec_b = timeval_of_packets.back().tv_usec;

  return (struct timeval) {
    tv_sec_a - tv_sec_b,
    //(int)(1000000-tv_usec_a-tv_usec_a)
    (int)(tv_usec_a-tv_usec_a>=0)?(tv_usec_a-tv_usec_a):(1000000-tv_usec_a-tv_usec_a)
  };
  /*
  return (struct timeval) {
    abs(timeval_of_packets.back().tv_sec-timeval_of_packets.front().tv_sec),
    abs(timeval_of_packets.back().tv_usec-timeval_of_packets.front().tv_usec)
  };*/
}

uint32_t Connection::get_number_packets_source_to_destination() {
  return this->numberPacketsSourceToDestination;
}
uint32_t Connection::get_number_packets_destination_to_source() {
  return this->numberPacketsDestinationToSource;
}
uint64_t Connection::get_number_bytes_source_to_destination() {
  return this->numberBytesSourceToDestination;
}
uint64_t Connection::get_number_bytes_destination_to_source() {
  return this->numberBytesDestinationToSource;
}

void Connection::add_packet(struct ip *ip, struct TCP_hdr *tcp) {
  this->ip_packet_headers.emplace_back(ip);
  this->tcp_packet_headers.emplace_back(tcp);
}

uint32_t Connection::get_number_packets() {
  return get_number_packets_source_to_destination() +
         get_number_packets_destination_to_source();
}

uint64_t Connection::get_number_bytes() {
  return get_number_bytes_source_to_destination() +
         get_number_bytes_destination_to_source();
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

int is_same_connection(struct ip *ip, struct TCP_hdr *tcp,
                       Connection *connection) {
  return _is_same_connection(
      ip->ip_src, ntohs(tcp->th_sport), ip->ip_dst, ntohs(tcp->th_dport),
      connection->get_source_address(), connection->get_source_port(),
      connection->get_destination_address(), connection->get_destination_port(),
      false);
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
std::string avg(std::vector<Connection> *vec,
                std::function<uint64_t(Connection)> f) {
  uint64_t value = f(vec->front());
  for (Connection i : *vec)
    value += f(i);
  return std::to_string(value / ((double)vec->size()));
}

/**
 * @param {vector<Conection>}
 * @param {std::function}
 * function f should be of the format:
 * [](Connection * c) {return c.%parameter%}
 */
std::string max(std::vector<Connection> *vec,
                std::function<uint64_t(Connection)> f) {
  uint64_t value = f(vec->front());
  for (Connection i : *vec)
    if (value < f(i))
      value = f(i);
  return std::to_string(value);
}

/**
 * @param {vector<Conection>}
 * @param {std::function}
 * function f should be of the format:
 * [](Connection * c) {return c.%parameter%}
 */
std::string min(std::vector<Connection> *vec,
                std::function<uint64_t(Connection)> f) {
  uint64_t value = f(vec->front());
  for (Connection i : *vec)
    if (value > f(i))
      value = f(i);
  return std::to_string(value);
}
