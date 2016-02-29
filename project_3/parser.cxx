/*******************************************************************************
 * @file parser.cxx
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

void print_output();

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
  if (pcap_compile(descr, &fp, "", 0, PCAP_NETMASK_UNKNOWN) == -1) {
    std::cerr << "Error calling pcap_compile\n";
    return EXIT_FAILURE;
  }

  /* set the compiled program as the filter */
  if (pcap_setfilter(descr, &fp) == -1) {
    std::cerr << "Error setting filter\n";
    return EXIT_FAILURE;
  }

  pcap_loop(descr, -1, got_packet, NULL);

  print_output();

  pcap_close(descr);

  return EXIT_SUCCESS;
}

/**
 * A Callback function used by pcap_loop that populates the global state
 * connections variable with data
 * @param {u_char *} args
 * @param {const struct pcap_pkthdr *} header
 * @param {const u_char *} packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
    // TODO
}

void print_output() {}
