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
 * Definitions Macros and Constants
*******************************************************************************/

#define MAX_TTL 30

/*******************************************************************************
 * Global Variables
*******************************************************************************/

std::vector<Packet> packets;

std::vector<Packet> request_packets;

/*******************************************************************************
 * Function Declarations
*******************************************************************************/

/**
 * @brief Does a very brief test to determine if the packet is a traceroute
 * request packet
 * @param packet a packet struct
 */
bool weak_is_traceroute_packet(Packet *packet);

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

/**
 * @brief Uses the id field in the IP header to match fragments
 * @param index the index in the list of the first fragment of the packet
 * @return a list of the fragments including the first fragment
 */
std::vector<Packet> get_fragments(uint64_t index);

struct icmphdr *get_icmp_header(const u_char *packet);

const u_char *get_payload_icmp(const u_char *packet);

int main(int argc, char **argv);

/*******************************************************************************
 * Function Definitions
*******************************************************************************/


bool is_same_packet_weak(Packet *a, Packet *b) {
  if (get_ether_header(a->packet)->ether_type != 0x800)
    return false;
  if (get_ether_header(b->packet)->ether_type != 0x800)
    return false;
  if (get_ip_header(a->packet)->ip_src.s_addr == get_ip_header(b->packet)->ip_src.s_addr &&
      get_ip_header(a->packet)->ip_dst.s_addr == get_ip_header(b->packet)->ip_dst.s_addr)
    return true;
  if (get_ip_header(a->packet)->ip_p == PROTOCOL_TYPE::UDP &&
      get_ip_header(b->packet)->ip_p == PROTOCOL_TYPE::UDP) {
    return get_udp_header(a->packet)->uh_dport ==
               get_udp_header(b->packet)->uh_dport &&
           get_udp_header(a->packet)->uh_sport ==
               get_udp_header(b->packet)->uh_sport;
  }
  return false;
}

bool is_same_packet_strict(Packet *a, Packet *b) {
  if (get_ether_header(a->packet)->ether_type != 0x800)
    return false;
  if (get_ether_header(b->packet)->ether_type != 0x800)
    return false;
  if (get_ip_header(a->packet)->ip_id == get_ip_header(b->packet)->ip_id)
    return is_same_packet_weak(a, b);
  return false;
}

bool is_same_src_dst (Packet *a, Packet *b) {
  return (get_ip_header(a->packet)->ip_src.s_addr==get_ip_header(b->packet)->ip_src.s_addr) &&
         (get_ip_header(a->packet)->ip_dst.s_addr==get_ip_header(b->packet)->ip_dst.s_addr);
}

bool is_same_packet_weak_ip(struct ip *a, struct ip *b) {
  if (a->ip_id == b->ip_id)
    return true;

  if (a->ip_p == PROTOCOL_TYPE::UDP && b->ip_p == PROTOCOL_TYPE::UDP) {
    struct udphdr *a_udp = (struct udphdr *)a + a->ip_hl * 4;
    struct udphdr *b_udp = (struct udphdr *)b + b->ip_hl * 4;
    return a_udp->uh_dport == b_udp->uh_dport &&
           a_udp->uh_sport == b_udp->uh_sport;
  }
  return false;
}
int64_t get_response(uint64_t index) {
  Packet *packet = &(packets.at(index));
  for (uint64_t i = index + 1; i < packets.size(); i++) {
    if (get_ether_header(packets.at(i).packet)->ether_type != 0x800 &&
        get_ip_header(packets.at(i).packet)->ip_p == PROTOCOL_TYPE::ICMP &&
        get_icmp_header((packets.at(i)).packet)->type==ICMP_TIME_EXCEEDED &&
        // TODO this ^- needs to be checked BSD not compatible
        true) {
      // std::cout << i+1 << "|" << print_packet(&(packets.at(i))) << std::endl;
      struct ip *ip_header =
          (struct ip *)get_payload_icmp(packets.at(i).packet);
      // std::cout << i+1 << "|" << htons(ip_header->ip_id) << std::endl;
      if (is_same_packet_weak_ip(get_ip_header(packet->packet), ip_header)) {
        return i;
      }
    }
  }
  return -1;
}

std::vector<Packet> get_fragments(uint64_t index) {
  std::vector<Packet> output;
  Packet *packet = &(packets.at(index));
  output.emplace_back(*packet);

  for (uint64_t i = index + 1; i < packets.size(); i++) {
    if (get_ether_header(packets.at(i).packet)->ether_type != 0x800) {
      struct ip *ip_header = (struct ip *)get_ip_header(packets.at(i).packet);
      if (is_same_packet_weak_ip(get_ip_header(packet->packet), ip_header)) {
        output.emplace_back((packets.at(i)));
      }
    }
  }

  return output;
}

struct timeval get_delta_time (Packet * a, Packet * b) {
  struct timeval output;
  timeval_subtract(&output, (a->header->ts), (b->header->ts));

  return output;
}


struct icmphdr *get_icmp_header(const u_char *packet) {
  const u_char *pointer =
      packet + sizeof(struct ether_header) + (get_ip_header(packet)->ip_hl * 4);
  return (struct icmphdr *)pointer;
}

const u_char *get_payload_icmp(const u_char *packet) {
  const u_char *pointer = packet + sizeof(struct ether_header) +
                          (get_ip_header(packet)->ip_hl * 4) +
                          8; // sizeof (struct icmphdr)
  return pointer;
}

/******************************************************************************/

// TODO/NOTE: The identification field in the linux udp trace file was modified
// Find a way to look at other fields to still match

std::vector<Packet *> compile_requests(void) {
  std::vector<Packet *> output;
  uint8_t ttl_tmp = 1;
  for (uint64_t i = 0; i < packets.size(); i++) {
    if (get_ip_header(packets.at(i).packet)->ip_ttl == ttl_tmp &&
        weak_is_traceroute_packet(&(packets.at(i)))) {
      output.emplace_back(&(packets.at(i)));
      ++ttl_tmp;
    }
  }
  return output;
}

std::vector<Packet *> compile_responses(void) {
  std::vector<Packet *> output;
  uint8_t ttl_tmp = 1;
  for (uint64_t i = 0; i < packets.size(); i++) {
    if (get_ip_header(packets.at(i).packet)->ip_ttl == ttl_tmp &&
        weak_is_traceroute_packet(&(packets.at(i)))) {
      for (uint64_t j = i + 1; j < packets.size(); j++) {
        if (get_ip_header(packets.at(j).packet)->ip_p == PROTOCOL_TYPE::ICMP) {
          struct icmphdr *icmp_packet = get_icmp_header(packets.at(j).packet);
          if(icmp_packet->type==ICMP_TIME_EXCEEDED)
          {
            struct ip *ip_header =
                (struct ip *)get_payload_icmp(packets.at(j).packet);
            if (ip_header->ip_id ==
                get_ip_header(packets.at(i).packet)->ip_id) {
              // std::cout << get_fragments(i).size() << std::endl;
              output.emplace_back(&(packets.at(j)));
            }
          }
        }
      }
      ++ttl_tmp;
    }
  }
  return output;
}

std::vector<std::string> compile_response_ips(std::vector<Packet *>) {
  std::vector<std::string> output;
  for (Packet *i : compile_responses()) {
    output.emplace_back(inet_ntoa(get_ip_header(i->packet)->ip_src));
  }
  return output;
}

bool weak_is_traceroute_packet(Packet *packet) {
  struct ether_header *ethernet_header = get_ether_header(packet->packet);
  struct ip *ip_header = get_ip_header(packet->packet);
  switch (ip_header->ip_p) {
  case 1: // ICMP
          // case 6: // TCP
    return true;
  case 17: // UDP
    struct udphdr *udp_header = get_udp_header(packet->packet);

    // UDP traceroute "unlikely UDP ports" unix taceroute defaultly uses
    // these ports
    return (ntohs(udp_header->uh_dport) >= 33434 &&
            ntohs(udp_header->uh_dport) <= 33534);
  }
  return false;
}

std::string protocol_number_to_string(uint8_t protocol) {
  switch (protocol) {
  case PROTOCOL_TYPE::ICMP:
    return "ICMP";
  case PROTOCOL_TYPE::UDP:
    return "UDP";
  case PROTOCOL_TYPE::TCP:
    return "TCP";
  default:
    return "OTHER";
  }
}

int get_first_traceroute_packet(std::vector<Packet> packets) {
  Packet *tmp;
  for (int i = 0; i < packets.size(); i++) {
    tmp = &(packets.at(i));
    // std::cout << i+1 << " " <<
    // protocol_number_to_string(get_ip_header(tmp->packet)->ip_p) << std::endl;
    if (get_ip_header(tmp->packet)->ip_ttl == 1 &&
        weak_is_traceroute_packet(tmp)) {
      return i;
    }
  }
  return -1;
}

void compile_hops(int64_t index) {
  if (index == -1)
    return;

  Packet first = packets.at(index);
  Packet *tmp;

  for (int i = 0; i < packets.size(); i++) {
    tmp = &(packets.at(i));
    if ((get_ip_header(first.packet)->ip_src.s_addr ==
         get_ip_header(packets.at(i).packet)->ip_src.s_addr) &&
        get_ip_header(first.packet)->ip_dst.s_addr ==
            get_ip_header(packets.at(i).packet)->ip_dst.s_addr) {
      request_packets.emplace_back(*tmp);
    }
  }
}

void print_output(void) {

  Packet first = packets.at(get_first_traceroute_packet(packets));
  std::vector<Packet *> requests = compile_requests();
  //std::vector<Packet *> responses = compile_responses();
  //std::vector<std::string> response_ips = compile_response_ips(responses);

/*
 *  Traceroute Source/Destination Info
*******************************************************************************/

  std::cout << "The IP address of the source node: "
            << inet_ntoa(get_ip_header(first.packet)->ip_src) << std::endl;

  std::cout << "The IP address of ultimate destination node: "
            << inet_ntoa(get_ip_header(first.packet)->ip_dst) << std::endl;

/*
 *  Intermediate Hop Info
*******************************************************************************/

  std::cout << "The IP addresses of the intermediate destination nodes: "
            << std::endl;

  for (uint32_t i = 0; i < requests.size(); i++) {
    int32_t j;
    if ((j = get_response(requests.at(i)->index)) != -1) {
      std::cout << "    "
                << "router " << i + 1 << ": "
                << inet_ntoa(get_ip_header(packets.at(j).packet)->ip_src)
                << std::endl;
    }
  }

  std::cout << std::endl;

/*
 *  Header Protocol Sumation
*******************************************************************************/

  std::map<uint8_t, uint64_t> protocols;

  for (int i = 0; i < packets.size(); i++) {
    uint8_t protocol = get_ip_header(packets.at(i).packet)->ip_p;
    protocols[protocol]++;
  }

  std::cout << "The values in the protocol field of IP headers: " << std::endl;
  for (auto i : protocols)
    std::cout << "    " << i.second << ": "
              << protocol_number_to_string(i.first) << std::endl;

  std::cout << std::endl;

/*
 *  Fragmentation Calculations
*******************************************************************************/

  for (uint32_t i = 0; i < requests.size(); i++) {
    std::vector<Packet> fragments = get_fragments(requests.at(i)->index);
    int32_t count = fragments.size();
    if (count > 1) {
      uint16_t offset = htons(get_ip_header(fragments.back().packet)->ip_off);
      std::cout << "    The number of fragments created from the original "
                   "datagram (Packet "
                << requests.at(i)->index + 1 << ") is: " << count << std::endl;

      std::cout << "    The offset of the last fragment is: "
                << std::to_string((offset & 0x1FFF) * 8) << std::endl
                << std::endl;
    }
  }

  std::cout << std::endl;


/*
 *  RTT Calculations
*******************************************************************************/

  for (uint32_t i = 0; i < requests.size(); i++) {
    std::vector<double> time_delta;
    uint32_t index = requests.at(i)->index;
    for(uint32_t j = index; j < packets.size(); j++) {
    	// NOTE: making assumption that traffic has IP header
    	if(get_ip_header(packets.at(index).packet)->ip_ttl == get_ip_header(packets.at(j).packet)->ip_ttl &&
    	    is_same_src_dst(&(packets.at(index)), &(packets.at(j))))
        {
  	    struct timeval result = (struct timeval) {0, 0};
  	    int64_t x = j;
        int64_t y = get_response(j);

  	    if(x!=-1 && y!=-1) {
  	      timeval_subtract(&result, packets.at(y).header->ts, packets.at(x).header->ts);
  	      time_delta.emplace_back(timestamp_to_ms(result));
  	    }
    	}
    }

    int32_t j;
    if ((j = get_response(requests.at(i)->index)) != -1) {
      double mean = 0.0;
      std::cout << "The avg RRT between "
		<< inet_ntoa(get_ip_header(first.packet)->ip_src)
    << " and ";
		std::cout << inet_ntoa(get_ip_header(packets.at(j).packet)->ip_src)
		<< " is: "
		<< (mean = std::accumulate(time_delta.begin(), time_delta.end(), 0.0, [&](double a, double b){
		  return a + b / time_delta.size();
		}))
		<< " ms, the s.d. is: "
		<< sqrt(std::accumulate(time_delta.begin(), time_delta.end(), 0.0, [&](double a, double b){
	          return pow(b - mean, 2.0);
	        }) / (time_delta.size() - 1))
		<< " ms"
		<< std::endl;
    }
  }
  std::cout << std::endl;
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
        ->emplace_back((Packet){header_copy, packet_copy, packets.size()});

  } catch (std::exception &e) {
    std::cerr << "Exception caught : " << e.what() << std::endl;
  }
}

int main(int argc, char **argv) {
  struct bpf_program fp;
  const u_char *packet;
  struct pcap_pkthdr header;
  char *filter = (char *)"";
  pcap_t *descr;
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

  // set the compiled program as the filter
  if (pcap_setfilter(descr, &fp) == -1) {
    std::cerr << "Error setting filter" << std::endl;
    return EXIT_FAILURE;
  }

  pcap_loop(descr, -1, got_packet, (u_char *)&packets);

  compile_hops(0);

  print_output();

  pcap_close(descr);

  return EXIT_SUCCESS;
}
