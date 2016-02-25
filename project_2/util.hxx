

#ifndef _UTIL_HXX
#define _UTIL_HXX

#include <iostream>
#include <string>
#include <ctime>
#include <cstdint>

#include <netinet/ip.h>

/* Returns a string representation of a timestamp. */
const char *timestamp_string(struct timeval ts);

int timeval_subtract(struct timeval *result, struct timeval *x,
                     struct timeval *y);


class Connection {
public:                       // begin public section
  Connection(); // constructor
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

private:


};



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
