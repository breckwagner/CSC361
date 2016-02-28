/*******************************************************************************
 * @file parser.cxx
 * @author Richard B. Wagner
 * @date 2016-02-27
 * @brief "Limited" TCP trace file parser
 *
 * "The purpose of this project is to learn about the Transmission Control
 * Protocol (TCP). You are required to write a C program with the pcap library
 * to analyze the TCP protocol behavior."
 *
 * @see CSc 361: Computer Communications and Networks (Spring 2016) Assignment 2
 ******************************************************************************/

#include "util.hxx"

// Global Variable holding the connection(s) state information
std::vector<Connection> connections;

void printOutput();

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);

/**
 *
 */
int main(int argc, char **argv) {
  struct bpf_program fp;

  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << "<pcap>\n";
    return EXIT_FAILURE;
  }

  pcap_t *descr;
  char errbuf[PCAP_ERRBUF_SIZE];
  descr = pcap_open_offline(argv[1], errbuf);

  if (descr == NULL) {
    std::cerr << "Couldn't open pcap file" << argv[1] << ": " << errbuf << "\n";
    return EXIT_FAILURE;
  }

  /* Lets try and compile the program.. non-optimized */
  if (pcap_compile(descr, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN) == -1) {
    std::cerr << "Error calling pcap_compile\n";
    return EXIT_FAILURE;
  }

  /* set the compiled program as the filter */
  if (pcap_setfilter(descr, &fp) == -1) {
    std::cerr << "Error setting filter\n";
    return EXIT_FAILURE;
  }

#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic push
  pcap_loop(descr, -1, got_packet, NULL);
#pragma GCC diagnostic pop

  printOutput();

  pcap_close(descr);

  return EXIT_SUCCESS;
}

/**
 * A Callback function used by pcap_loop that populates the global state
 * connections variable with data
 * @param {u_char *} args,
 * @param {const struct pcap_pkthdr *} header
 * @param {const u_char *} packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
  try {
    if (!is_header_intact(header, packet))
      return;
    struct pcap_pkthdr *header_copy =
        (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
    u_char *packet_copy = (u_char *)malloc(header->caplen);

    memmove(header_copy, header, sizeof(struct pcap_pkthdr));
    memmove(packet_copy, packet, header->caplen);

    Connection tmp_1 = Connection(header_copy, packet_copy);
    bool flag = true;

    for (Connection &tmp_2 : connections) {
      flag = (flag && !is_same_connection(&tmp_1, &tmp_2));
      if (is_same_connection(&tmp_1, &tmp_2)) {
        tmp_2.add_packet(packet_copy, header_copy);
      }
    }

    if (flag)
      connections.emplace_back(tmp_1);

  } catch (std::exception &e) {
    std::cerr << "Exception catched : " << e.what() << std::endl;
  }
}

/**
 * Prints the statistics from the TCP trace file parser to the screen
 */
void printOutput() {
  std::size_t n = 0;
  struct timeval offset = get_relative_time(connections);

  std::cout << "\nA) Total number of connections: "
            << std::to_string(connections.size()) << std::endl;

  std::cout << std::endl << std::string(80, '-') << std::endl;

  std::cout << std::endl << "B) Connections' details:\n" << std::endl;

  for (Connection i : connections) {

    std::cout << std::endl
              << "Connection " << std::to_string(++n) << ":" << std::endl;

    std::cout << "     Source Address: " << inet_ntoa(i.get_source_address())
              << std::endl;

    std::cout << "Destination Address: "
              << inet_ntoa(i.get_destination_address()) << std::endl;

    std::cout << "        Source Port: " << std::to_string(i.get_source_port())
              << std::endl;

    std::cout << "   Destination Port: "
              << std::to_string(i.get_destination_port()) << std::endl;

    std::cout << "             Status: " << status_to_string(i.get_status())
              << std::endl;

    // If the connection is complete
    if (i.get_status().syn != 0 && i.get_status().fin != 0 &&
        i.get_status().rst == 0) {

      std::cout << std::string(39, ' ')
                << "End Time: " << timeval_subtract(i.get_end_time(), offset)
                << std::endl;

      std::cout << std::string(39, ' ')
                << "Duration: " << timestamp_string(i.get_duration())
                << std::endl;

      std::cout << "   # of packets sent from Source to Destination: "
                << std::to_string(i.get_number_packets_source_to_destination())
                << std::endl;

      std::cout << "   # of packets sent from Destination to Source: "
                << std::to_string(i.get_number_packets_destination_to_source())
                << std::endl;

      std::cout << "                        Total number of packets: "
                << std::to_string(i.get_number_packets_source_to_destination() +
                                  i.get_number_packets_destination_to_source())
                << std::endl;

      std::cout << "# of data bytes sent from Source to Destination: "
                << std::to_string(i.get_number_bytes_source_to_destination())
                << std::endl;

      std::cout << "# of data bytes sent from Destination to Source: "
                << std::to_string(i.get_number_bytes_destination_to_source())
                << std::endl;

      std::cout << "                     Total number of data bytes: "
                << std::to_string(i.get_number_bytes_source_to_destination() +
                                  i.get_number_bytes_destination_to_source())
                << std::endl;
    }
    std::cout << "END" << std::endl;

    if (n - connections.size() > 0)
      std::cout << std::string(60, '+');
  }

  std::cout << std::endl << std::string(80, '-') << std::endl;

  std::cout << std::endl << "C) General" << std::endl;

  std::cout << "Total number of complete TCP connections: "
            << std::to_string([]() {
                 uint64_t n = 0;
                 for (Connection i : connections)
                   if (i.get_status().syn != 0 && i.get_status().fin != 0 &&
                       i.get_status().rst == 0)
                     n++;
                 return n;
               }())
            << std::endl;

  std::cout << "Number of reset TCP connections: " << std::to_string([]() {
    uint64_t n = 0;
    for (Connection i : connections)
      if (i.get_status().rst != 0)
        n++;
    return n;
  }()) << std::endl;

  std::cout << "Number of TCP connections that were still open when the trace "
               "capture ended: "
            << std::to_string([]() {
                 uint64_t n = 0;
                 for (Connection i : connections)
                   if (i.get_status().fin == 0 && i.get_status().rst == 0)
                     n++;
                 return n;
               }())
            << std::endl;

  std::cout << std::endl << std::string(80, '-') << std::endl;

  std::cout << std::endl << "D) Complete TCP connections:" << std::endl;

  std::cout << "Minimum time durations: " << []() {
    struct timeval min = connections.front().get_duration();
    for (Connection i : connections)
      if (_timercmp(i.get_duration(), min, < ))
        min = i.get_duration();
    return timestamp_string(min);
  }() << std::endl;

  std::cout << "Mean time durations:    " << []() {
    uint64_t tv_sec = 0;
    uint64_t tv_usec = 0;
    for (Connection i : connections) {
      tv_sec += i.get_duration().tv_sec;
      tv_usec += i.get_duration().tv_sec;
    }
    return timestamp_string(
        (struct timeval){(time_t)(tv_sec / connections.size()),
                         (uint16_t)(tv_usec / connections.size())});
  }() << std::endl;

  std::cout << "Maximum time durations: " << []() {
    struct timeval max = connections.front().get_duration();
    for (Connection i : connections)
      if (_timercmp(i.get_duration(), max, > ))
        max = i.get_duration();
    return timestamp_string(max);
  }() << std::endl;

  std::cout << "Minimum RTT values including both send/received: "
  /*          << ([]() {
              uint64_t value =
                  get_tcp_header(connections.front().packets.front())->th_win;
              for (Connection i : connections)
                for (const u_char *j : i.packets) {
                  uint64_t tmp = get_tcp_header(j)->th_win;
                  if (tmp < value)
                    value = tmp;
                }
              return value;
            })()*/
            << std::endl;

  std::cout << "Mean RTT values including both send/received:    "
            //<< avg(&connections, [](Connection c) { return 0; })
            << std::endl;

  std::cout << "Maximum RTT values including both send/received: "
  /*
  std::max_element(connections.begin(), connections.end(),
                   ([](const Connection &i, const Connection &j) {
                     return i.get_number_packets() < j.get_number_packets();

                   }))
      ->get_number_packets();
      */
            << std::endl;

  std::cout << "Minimum number of packets including both send/received: "
            << std::min_element(connections.begin(), connections.end(),
                                ([](const Connection &i, const Connection &j) {
                                  return i.get_number_packets() <
                                         j.get_number_packets();
                                }))
                   ->get_number_packets()
            << std::endl;

  std::cout << "Mean number of packets including both send/received:    "
            << avg(&connections, [](Connection c) {
                 return c.get_number_packets();
               }) << std::endl;

  std::cout << "Maximum number of packets including both send/received: "
            << std::max_element(connections.begin(), connections.end(),
                                ([](const Connection &i, const Connection &j) {
                                  return i.get_number_packets() <
                                         j.get_number_packets();
                                }))
                   ->get_number_packets()
            << std::endl;

  // NOTE: this section should be changed to not use the internal packets
  // variable. Additionally, these lambda expressions should be made into macros
  // or included in the Connection class
  std::cout << "Minimum receive window sizes including both send/received: "
            << ([]() {
                 uint64_t value =
                     get_tcp_header(connections.front().packets.front())
                         ->th_win;
                 for (Connection i : connections)
                   for (const u_char *j : i.packets) {
                     uint64_t tmp = get_tcp_header(j)->th_win;
                     if (tmp < value)
                       value = tmp;
                   }
                 return value;
               })()
            << std::endl;

  std::cout << "Mean receive window sizes including both send/received:    "
            << ([]() {
                 double n = 0;
                 uint64_t value =
                     get_tcp_header(connections.front().packets.front())
                         ->th_win;
                 for (Connection i : connections)
                   for (const u_char *j : i.packets) {
                     value += get_tcp_header(j)->th_win;
                     n++;
                   }
                 return value / n;
               })()
            << std::endl;

  std::cout << "Maximum receive window sizes including both send/received: "
            << ([]() {
                 uint64_t value =
                     get_tcp_header(connections.front().packets.front())
                         ->th_win;
                 for (Connection i : connections)
                   for (const u_char *j : i.packets) {
                     uint64_t tmp = get_tcp_header(j)->th_win;
                     if (tmp > value)
                       value = tmp;
                   }
                 return value;
               })()
            << std::endl;

  std::cout << std::endl << std::endl;
}
