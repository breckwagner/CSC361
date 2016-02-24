

#ifndef _UTIL_HXX
#define _UTIL_HXX

#include <iostream>
#include <string>
#include <ctime>
#include <cstdint>

#include <netinet/ip.h>

/* Returns a string representation of a timestamp. */
const char *timestamp_string(struct timeval ts);


class Connection {
public:                       // begin public section
  Connection(); // constructor
  //Connection(const Connection &copy_from); // copy constructor
  //Connection &operator=(const Connection &copy_from); // copy assignment
  ~Connection(); // destructor

  struct in_addr * sourceAddress;
  struct in_addr * destinationAddress;
  uint16_t sourcePort;
  uint16_t destinationPort;
  struct timeval endTime;
  struct timeval duration;

  uint32_t numberPacketsSourceToDestination;
  uint32_t numberPacketsDestinationToSource;

  uint64_t numberBytesSourceToDestination;
  uint64_t numberBytesDestinationToSource;
private:


};
#endif
