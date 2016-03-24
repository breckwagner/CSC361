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

#define MAX_TTL 30

void print_output(std::vector<Packet> packets);

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);

std::vector<Packet> request_packets;

bool vet_traceroute (Packet * packet) {
  struct ether_header * ethernet_header = get_ether_header(packet->packet);
  struct ip * ip_header = get_ip_header(packet->packet);
  switch (ip_header->ip_p) {
    case 1: // ICMP
    case 6: // TCP
      return true;
    case 17: // UDP
      struct udphdr * udp_header = get_udp_header(packet->packet);

      // UDP traceroute "unlikely UDP ports"
      return (ntohs(udp_header->uh_dport) >= 33434 &&
              ntohs(udp_header->uh_dport) <= 33534);
  }
  return false;
}

/*
*/
int get_first_traceroute_packet(std::vector<Packet> packets) {
  Packet * tmp;
  for (int i = 0; i < packets.size(); i++) {
    tmp = &(packets.at(i));
    if (get_ip_header(tmp->packet)->ip_ttl == 1 && vet_traceroute(tmp)) {
      return i;
    }
  }
  return -1;
}

void compile_hops(std::vector<Hop> *hops, std::vector<Packet> packets) {
  int index_first = get_first_traceroute_packet(packets);
  if(index_first == -1) return;

  Packet first = packets.at(index_first);
  Packet * tmp;

  for (int i = 0; i < packets.size(); i++) {
    tmp = &(packets.at(i));
    if ((get_ip_header(first.packet)->ip_src.s_addr ==
        get_ip_header(packets.at(i).packet)->ip_src.s_addr) &&
        get_ip_header(first.packet)->ip_dst.s_addr ==
        get_ip_header(packets.at(i).packet)->ip_dst.s_addr){
      request_packets.emplace_back(*tmp);
    }
  }

  std::cout << request_packets.size() << std::endl;


/*
  // Find traceroute request packets
  for(uint8_t ttl = 1; ttl <= MAX_TTL; ttl++) {
    Hop tmp_hop;
    hops->emplace_back(tmp_hop);
    for (int i = 0; i < packets.size(); i++) {
      if (get_ip_header(first.packet)->ip_src.s_addr ==
          get_ip_header(packets.at(i).packet)->ip_src.s_addr) {
        tmp = &(packets.at(i));
        uint8_t ttl_tmp = get_ip_header(tmp->packet)->ip_ttl;
        if(vet_traceroute(tmp) && ttl_tmp == ttl) {
          //hops->at(ttl).request_packets.insert(hops->at(ttl).request_packets.begin(),packets.at(i));
          std::cout << i << std::endl;
        }
      }
    }
    // If no request packet with specified ttl, assume tracerout finished
    if (hops->at(ttl) == NULL) {
      hops->pop_back();
      break;
    }

  }


  // Find traceroute response packets


  for (int i = 0; i < packets.size(); i++) {
    if (get_ip_header(first.packet)->ip_src.s_addr ==
        get_ip_header(packets.at(i).packet)->ip_src.s_addr) {
      for(int j = 0; j < hops->size(); j++) {
        if(true) {

          //hops->insert ( hops->begin() , 200 );
        }
      }
    }
  }
  */
}

/**
 *
 */
int main(int argc, char **argv) {
  std::vector<Packet> packets;
  std::vector<Hop> hops;
  struct bpf_program fp;
  char *filter = (char *)"";

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
  if (pcap_compile(descr, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
    std::cerr << "Error calling pcap_compile\n";
    return EXIT_FAILURE;
  }

  /* set the compiled program as the filter */
  if (pcap_setfilter(descr, &fp) == -1) {
    std::cerr << "Error setting filter\n";
    return EXIT_FAILURE;
  }

  pcap_loop(descr, -1, got_packet, (u_char *)&packets);

  compile_hops(&hops, packets);

  print_output(packets);

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
  try {
    struct pcap_pkthdr *header_copy =
        (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
    u_char *packet_copy = (u_char *)malloc(header->caplen);

    memmove(header_copy, header, sizeof(struct pcap_pkthdr));
    memmove(packet_copy, packet, header->caplen);

    ((std::vector<Packet> *)args)
        ->emplace_back((Packet){header_copy, packet_copy});

  } catch (std::exception &e) {
    std::cerr << "Exception caught : " << e.what() << std::endl;
  }
}

/**
 * A utility function used to print out data in the specified format
 * @param {u_char *} args is
 */
void print_output(std::vector<Packet> packets) {

  Packet first = packets.at(get_first_traceroute_packet(packets));

  std::cout << "The IP address of the source node: "
            << inet_ntoa(get_ip_header(first.packet)->ip_src) << std::endl;

  std::cout << "The IP address of ultimate destination node: "
            << inet_ntoa(get_ip_header(first.packet)->ip_dst) << std::endl;

  std::cout << "The IP addresses of the intermediate destination nodes: "
            << std::endl;

  /*
    for(int i = 0; i < packets.size(); i++) {
      std::cout << "router " << i + 1 << ": "
                << ""
                << std::endl;
    }
  */

  std::cout << "The values in the protocol field of IP headers: "
            << "" << std::endl;

  std::cout << "The number of fragments created from the original datagram is: "
            << "" << std::endl;

  std::cout << "The offset of the last fragment is: "
            << "" << std::endl;

  std::cout << "The avg RRT between "
            << ""
            << " and "
            << ""
            << " is: "
            << ""
            << " ms, the s.d. is: "
            << ""
            << " ms"
            << "" << std::endl;
}
