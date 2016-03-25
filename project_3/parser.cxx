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
*******************************************************************************/

/*******************************************************************************
 * Includes
*******************************************************************************/

#include "util.hxx"

/*******************************************************************************
 * Definitions
*******************************************************************************/

#define MAX_TTL 30

/*******************************************************************************
 * Global Variables
*******************************************************************************/

std::vector<Packet> packets;

std::vector<Packet> request_packets;

std::vector<Packet> response_packets;

std::vector<std::string> response_ips;

std::map<uint8_t,uint64_t> protocols;

/*******************************************************************************
 * Function Declarations
*******************************************************************************/

/**
 * @brief Does a very brief test to determine if the packet is a traceroute
 * request packet
 * @param packet a packet struct
 */
bool weak_is_traceroute_packet (Packet * packet);

int get_first_traceroute_packet(std::vector<Packet> packets);

/**
 * A utility function used to print out data in the specified format
 * @param {u_char *} args is
 */
void print_output(void);

/**
 * A Callback function used by pcap_loop that populates the global state
 * connections variable with data
 * @param {u_char *} args
 * @param {const struct pcap_pkthdr *} header
 * @param {const u_char *} packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);

int main(int argc, char **argv);

/*******************************************************************************
 * Function Definitions
*******************************************************************************/

struct timeval get_packet_timestamp (Packet * packet) {
  return (struct timeval) {
    packet->header->ts.tv_sec,
    packet->header->ts.tv_usec
  };
}

struct icmphdr * get_icmp_header(const u_char *packet) {
  const u_char *pointer =
      packet + sizeof(struct ether_header) + (get_ip_header(packet)->ip_hl * 4);
  return (struct icmphdr *)pointer;
}

const u_char *get_payload_icmp(const u_char *packet) {
  const u_char *pointer = packet + sizeof(struct ether_header) +
                          (get_ip_header(packet)->ip_hl * 4) +
                          sizeof(struct icmphdr);
  return pointer;
}

/******************************************************************************/

// TODO/NOTE: The identification field in the linux udp trace file was modified
// Find a way to look at other fields to still match
void compile_response_ips (void) {
  uint8_t ttl_tmp = 1;
  std::cout << "first: " << get_first_traceroute_packet(packets) << std::endl;
  for (uint64_t i = 0; i < packets.size(); i++){
    if (get_ip_header(packets.at(i).packet)->ip_ttl == ttl_tmp && weak_is_traceroute_packet(&(packets.at(i)))){
      for (uint64_t j = i+1; j < packets.size(); j++){
        if (get_ip_header(packets.at(j).packet)->ip_p==PROTOCOL_TYPE::ICMP) {
          struct icmphdr * icmp_packet = get_icmp_header(packets.at(j).packet);
          //if(icmp_packet->type==ICMP_TIME_EXCEEDED)
          {
            struct ip * ip_header = (struct ip *) get_payload_icmp(packets.at(j).packet);
            if (ip_header->ip_id == get_ip_header(packets.at(i).packet)->ip_id)
            {
              std::cout << "i:" << i << "| j:" << j << std::endl;
              std::cout << ip_header->ip_id << std::endl;
              response_ips.emplace_back(inet_ntoa(get_ip_header(packets.at(j).packet)->ip_src));
            }
          }
        }
      }
      ++ttl_tmp;
    }
  }
}

bool weak_is_traceroute_packet (Packet * packet) {
  struct ether_header * ethernet_header = get_ether_header(packet->packet);
  struct ip * ip_header = get_ip_header(packet->packet);
  switch (ip_header->ip_p) {
    case 1: // ICMP
    //case 6: // TCP
      return true;
    case 17: // UDP
      struct udphdr * udp_header = get_udp_header(packet->packet);

      // UDP traceroute "unlikely UDP ports" unix taceroute defaultly uses
      // these ports
      return (ntohs(udp_header->uh_dport) >= 33434 &&
              ntohs(udp_header->uh_dport) <= 33534);
  }
  return false;
}

std::string protocol_number_to_string (uint8_t protocol) {
  switch (protocol) {
    case PROTOCOL_TYPE::ICMP: return "ICMP";
    case PROTOCOL_TYPE::UDP: return "UDP";
    case PROTOCOL_TYPE::TCP: return "TCP";
    default: return "UNKNOWN";
  }
}

int get_first_traceroute_packet(std::vector<Packet> packets) {
  Packet * tmp;
  for (int i = 0; i < packets.size(); i++) {
    tmp = &(packets.at(i));
    std::cout << i+1 << " " << protocol_number_to_string(get_ip_header(tmp->packet)->ip_p) << std::endl;
    if (get_ip_header(tmp->packet)->ip_ttl == 1 && weak_is_traceroute_packet(tmp)) {
      return i;
    }
  }
  return -1;
}

void compile_hops(std::vector<Hop> *hops) {
  int index_first = 0;
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
}

void print_output(void) {

  Packet first = packets.at(get_first_traceroute_packet(packets));

  std::cout << "The IP address of the source node: "
            << inet_ntoa(get_ip_header(first.packet)->ip_src) << std::endl;

  std::cout << "The IP address of ultimate destination node: "
            << inet_ntoa(get_ip_header(first.packet)->ip_dst) << std::endl;

  std::cout << "The IP addresses of the intermediate destination nodes: "
            << std::endl;


    for(int i = 0; i < response_ips.size(); i++) {
      std::cout << "router " << i + 1 << ": "
                << response_ips.at(i)
                << std::endl;
    }


  for(int i = 0; i < packets.size(); i++) {
    uint8_t protocol = get_ip_header(packets.at(i).packet)->ip_p;
    //if (std::find(std::begin(protocols), std::end(protocols), protocol) == std::end(protocols))

    {
      protocols[protocol]++;
    }
  }
  std::cout << "The values in the protocol field of IP headers: " << std::endl;
  for (auto i : protocols)
    std::cout << i.second << ":" << protocol_number_to_string(i.first) << std::endl;

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

int main(int argc, char **argv) {
  std::vector<Hop> hops;
  struct bpf_program fp;
  const u_char * packet;
  struct pcap_pkthdr header;
  char * filter = (char *)"";
  pcap_t * descr;
  char errbuf[PCAP_ERRBUF_SIZE];
  Packet first_traceroute_packet;

  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << "<pcap>\n";
    return EXIT_FAILURE;
  }

  if ((descr = pcap_open_offline(argv[1], errbuf)) == NULL) {
    std::cerr << "Couldn't open pcap file" << argv[1] << ": " << errbuf << "\n";
    return EXIT_FAILURE;
  }

  // Lets try and compile the program.. non-optimized
  if (pcap_compile(descr, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
    std::cerr << "Error calling pcap_compile" << std::endl;
    return EXIT_FAILURE;
  }

  /* set the compiled program as the filter */
  if (pcap_setfilter(descr, &fp) == -1) {
    std::cerr << "Error setting filter" << std::endl;
    return EXIT_FAILURE;
  }

  while (true) {
    if ((packet = pcap_next(descr, &header)) != NULL) {
      Packet p = (Packet){&header, packet};
      if (weak_is_traceroute_packet(&p)) {
        first_traceroute_packet = p;
        std::string output;
        std::string src(inet_ntoa(get_ip_header(p.packet)->ip_src));
        std::string dst(inet_ntoa(get_ip_header(p.packet)->ip_dst));
        output = "ip.src==" + src + "&& ip.dst==" + dst;

        //filter = (char *) output.c_str();
        break;
      }
    } else {
      std::cerr << "Couldn't find a traceroute packet" << std::endl;
      return EXIT_FAILURE;
    }
  }

  // Lets try and compile the program.. non-optimized
  if (pcap_compile(descr, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
    std::cerr << "Error calling pcap_compile" << std::endl;
    return EXIT_FAILURE;
  }

  // set the compiled program as the filter
  if (pcap_setfilter(descr, &fp) == -1) {
    std::cerr << "Error setting filter" << std::endl;
    return EXIT_FAILURE;
  }

  pcap_loop(descr, -1, got_packet, (u_char *)&packets);

  compile_response_ips();

  compile_hops(&hops);

  print_output();

  pcap_close(descr);

  return EXIT_SUCCESS;
}
