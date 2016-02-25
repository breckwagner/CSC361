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
/*
Connection::Connection(const Connection &copy_from) {
  this->sourceAddress = copy_from.sourceAddress;
  this->destinationAddress = copy_from.destinationAddress;
  this->sourcePort = copy_from.sourcePort;
  this->destinationPort = copy_from.destinationPort;
  this->endTime = copy_from.endTime;
  this->duration = copy_from.duration;

  this->numberPacketsSourceToDestination = copy_from.numberPacketsSourceToDestination;
  this->numberPacketsDestinationToSource = copy_from.numberPacketsDestinationToSource;

  this->numberBytesSourceToDestination = copy_from.numberBytesSourceToDestination;
  this->numberBytesDestinationToSource = copy_from.numberBytesDestinationToSource;
}*/
/*
Connection &Connection::operator=(const Connection &copy_from) {
  sourceAddress = copy_from.sourceAddress;
  destinationAddress = copy_from.destinationAddress;
  sourcePort = copy_from.sourcePort;
  destinationPort = copy_from.destinationPort;
  endTime = copy_from.endTime;
  duration = copy_from.duration;

  numberPacketsSourceToDestination = copy_from.numberPacketsSourceToDestination;
  numberPacketsDestinationToSource = copy_from.numberPacketsDestinationToSource;

  numberBytesSourceToDestination = copy_from.numberBytesSourceToDestination;
  numberBytesDestinationToSource = copy_from.numberBytesDestinationToSource;
  return *this;
}
*/
Connection::~Connection() {}

void Connection::set_source_address(struct in_addr new_value) {
  this->sourceAddress = new_value;
}
void Connection::set_destination_address(struct in_addr new_value) {
  this->destinationAddress = new_value;
}
void Connection::set_source_port(uint16_t new_value){
  this->sourcePort = new_value;
}
void Connection::set_destination_port(uint16_t new_value){
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
uint16_t Connection::get_source_port() {
  return this->sourcePort;
}
uint16_t Connection::get_destination_port() {
  return this->destinationPort;
}
struct timeval Connection::get_end_time() {
  return this->endTime;
}
struct timeval Connection::get_duration() {
  return this->duration;
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






/* Note, this routine returns a pointer into a static buffer, and
 * so each call overwrites the value returned by the previous call.
 */
const char *timestamp_string(struct timeval ts) {
  static char timestamp_string_buf[256];

  sprintf(timestamp_string_buf, "%d.%06d", (int)ts.tv_sec, (int)ts.tv_usec);

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
