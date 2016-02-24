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

Connection::Connection(const Connection &copy_from) {}

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
}

Connection::~Connection() {}

/* Note, this routine returns a pointer into a static buffer, and
 * so each call overwrites the value returned by the previous call.
 */
const char *timestamp_string(struct timeval ts) {
  static char timestamp_string_buf[256];

  sprintf(timestamp_string_buf, "%d.%06d", (int)ts.tv_sec, (int)ts.tv_usec);

  return timestamp_string_buf;
}
