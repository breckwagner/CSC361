/*******************************************************************************
 * @file parser.cxx
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
using namespace std;



// Global Variable holding the connection(s) state information
std::vector<Connection> connections;

void printOutput();

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);

/**
 *
 */
int main(int argc, char **argv) {
  unsigned int packet_counter = 0;
  struct pcap_pkthdr header;
  const u_char *packet;
  struct bpf_program fp; /* hold compiled program     */
  bpf_u_int32 maskp;     /* subnet mask               */
  bpf_u_int32 netp;      /* ip                        */

  if (argc < 2) {
    cerr << "Usage: " << argv[0] << "<pcap>\n";
    return EXIT_FAILURE;
  }

  pcap_t *descr;
  char errbuf[PCAP_ERRBUF_SIZE];
  descr = pcap_open_offline(argv[1], errbuf);

  if (descr == NULL) {
    cerr << "Couldn't open pcap file" << argv[1] << ": " << errbuf << "\n";
    return EXIT_FAILURE;
  }

  /* Lets try and compile the program.. non-optimized */
  if (pcap_compile(descr, &fp, "tcp", 0, netp) == -1) {
    cerr << "Error calling pcap_compile\n";
    return EXIT_FAILURE;
  }

  /* set the compiled program as the filter */
  if (pcap_setfilter(descr, &fp) == -1) {
    cerr << "Error setting filter\n";
    return EXIT_FAILURE;
  }

  pcap_loop(descr, -1, got_packet, NULL);

  printOutput();

  pcap_close(descr);

  return EXIT_SUCCESS;
}

/**
 *
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
  static uint64_t count = 0;
  uint32_t capture_length = header->caplen;
  uint32_t ip_header_length;
  struct ip *ip;
  struct TCP_hdr *tcp;
  bool isNewConnection = true;
  struct timeval tmp_time;
  struct timeval tmp_time_2 = header->ts;

  static struct timeval offset = header->ts;

  if (timeval_subtract(&tmp_time, &tmp_time_2, &offset) == 1) {
    offset = tmp_time_2;
  }

  if (capture_length < sizeof(struct ether_header)) {
    return;
  }

  // Skip over the Ethernet header.
  packet += sizeof(struct ether_header);
  capture_length -= sizeof(struct ether_header);

  if (capture_length < sizeof(struct ip)) {
    return;
  }

  ip = (struct ip *)packet;
  ip_header_length = ip->ip_hl * 4; /* ip_hl is in 4-byte words */

  if (capture_length < ip_header_length) {
    return;
  }

  // Skip over the IP header.
  packet += ip_header_length;
  capture_length -= ip_header_length;

  tcp = (struct TCP_hdr *)packet;

  packet += tcp->th_off * 4;
  capture_length -= tcp->th_off * 4;
  Connection tmp_1;
  for (Connection &tmp_2 : connections) {
    // TODO MEMORY LEAK
    tmp_1 = Connection(ip, tcp);
    isNewConnection = (isNewConnection && !is_same_connection(&tmp_1, &tmp_2));

    if (is_same_connection(&tmp_1, &tmp_2) &&
        !is_same_connection(&tmp_1, &tmp_2, false) ) {
      tmp_2.set_number_packets_source_to_destination(tmp_2.get_number_packets_source_to_destination()+1);
    } else if (is_same_connection(&tmp_1, &tmp_2, false)) {
      tmp_2.set_number_packets_destination_to_source(tmp_2.get_number_packets_destination_to_source()+1);
    } else {

    }
  }

  if (isNewConnection) {
    Connection new_connection = Connection(ip, tcp);
    connections.emplace_back(new_connection);
  }
}

/**
 * Prints the statistics from the TCP trace file parser to the screen
 */
void printOutput() {
  std::string result = "";
  std::size_t n = 0;

  cout << "\nA) Total number of connections: " +
              std::to_string(connections.size());

  cout << "\n----------------------------------------------------------------"
          "----------------\n";

  cout << "\nB) Connections' details:\n";

  // for (std::vector<int>::iterator it = fifth.begin(); it != fifth.end();
  // ++it)

  for (Connection i : connections) {
    cout << "\n\tConnection " << std::to_string(++n) << ":";

    cout << "\n\t     Source Address: " << inet_ntoa(i.get_source_address());
    cout << "\n\tDestination Address: "
         << inet_ntoa(i.get_destination_address());
    cout << "\n\t        Source Port: " << std::to_string(i.get_source_port());
    cout << "\n\t   Destination Port: "
         << std::to_string(i.get_destination_port());

    cout << "\n\t             Status: ";

    // (Only if the connection is complete provide the following information)
    // Start time:
    cout << "\n\t                                       End Time:";
    cout << "\n\t                                       Duration:";
    cout << "\n\t   # of packets sent from Source to Destination:" << std::to_string(i.get_number_packets_source_to_destination());
    cout << "\n\t   # of packets sent from Destination to Source:" << std::to_string(i.get_number_packets_destination_to_source());
    cout << "\n\t                        Total number of packets:";
    cout << "\n\t# of data bytes sent from Source to Destination:";
    cout << "\n\t# of data bytes sent from Destination to Source:";
    cout << "\n\t                     Total number of data bytes:";
    cout << "\n\tEND";

    if (n - connections.size() > 0)
        cout << "\n" << std::string(80, '+');
  }

  cout << "\n" << std::string(80, '-') << "\n";

  cout << "\nC) General\n";
  cout << "\nTotal number of complete TCP connections:";
  cout << "\nNumber of reset TCP connections:";
  cout << "\nNumber of TCP connections that were still open when the trace "
          "capture ended:";

  cout << "\n" << std::string(80, '-') << "\n";

  uint64_t value;

  cout << "\nD) Complete TCP connections:\n";
  cout << "\nMinimum time durations: ";
  cout << "\nMean time durations: ";
  cout << "\nMaximum time durations:";

  cout << "\nMinimum RTT values including both send/received: ";
  cout << "\nMean RTT values including both send/received: ";
  cout << "\nMaximum RTT values including both send/received:";

  cout << "\nMinimum number of packets including both send/received: ";
  value = connections.front().get_number_packets();
  for (Connection i : connections)
    if(value > i.get_number_packets())
      value = i.get_number_packets();
  cout << std::to_string(value);


  cout << "\nMean number of packets including both send/received: ";
  value = connections.front().get_number_packets();
  for (Connection i : connections)
    value += i.get_number_packets();
  cout << std::to_string(value/((double) connections.size()));

  cout << "\nMaximum number of packets including both send/received:";
  value = connections.front().get_number_packets();
  for (Connection i : connections)
    if(value < i.get_number_packets())
      value = i.get_number_packets();
  cout << std::to_string(value);

  cout << "\nMinimum receive window sizes including both send/received: ";
  cout << "\nMean receive window sizes including both send/received: ";
  cout << "\nMaximum receive window sizes including both send/received:";

}
