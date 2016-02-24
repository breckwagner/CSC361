/*******************************************************************************
 * @file parser.c
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

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>

 #include <netinet/in.h>
 #include <netinet/ip.h>
 #include <net/if.h>
 #include <netinet/if_ether.h>

 #include <pcap.h>


 /**
  * @brief Data Connection
  *
  * TODO: Detailed explanation.
  */
 typedef struct Node Node;
 struct Node {
     int data;
     Node *nextptr;
 };


void printOutput ();




/**
 * Prints the statistics from the TCP trace file parser to the screen
 */
void printOutput () {



}



int main(int argc, char **argv)
{
  unsigned int packet_counter=0;
  struct pcap_pkthdr header;
  const u_char *packet;

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <pcap>\n", argv[0]);
    exit(1);
  }

   pcap_t *handle;
   char errbuf[PCAP_ERRBUF_SIZE];
   handle = pcap_open_offline(argv[1], errbuf);

   if (handle == NULL) {
     fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], errbuf);
     return(2);
   }

   while (packet = pcap_next(handle,&header)) {

      packet_counter++;

    }
    pcap_close(handle);


  printf("%d\n", packet_counter);
  return 0;
}







/*
A) Total number of connections:
B) Connections' details:
Connection 1: Source Address: Destination address: Source Port: Destination Port: Status:
(Only if the connection is complete provide the following information) Start time:
End Time:
Duration:
Number of packets sent from Source to Destination: Number of packets sent from Destination to Source: Total number of packets:
Number of data bytes sent from Source to Destination: Number of data bytes sent from Destination to Source: Total number of data bytes:
END
+++++++++++++++++++++++++++++++++
.
.
.
+++++++++++++++++++++++++++++++++
Connection N:
Source Address:
Destination address:
Source Port:
Destination Port:
Status:
Duration:
(Only if the connection is complete provide the following information) Start time:
End Time:
Number of packets sent from Source to Destination:
Number of packets sent from Destination to Source:
Total number of packets:
Number of data bytes sent from Source to Destination:
Number of data bytes sent from Destination to Source:
Total number of data bytes:
END

C) General
Total number of complete TCP connections:
Number of reset TCP connections:
Number of TCP connections that were still open when the trace capture ended:
D) Complete TCP connections:
Minimum time durations: Mean time durations: Maximum time durations:
Minimum RTT values including both send/received: Mean RTT values including both send/received: Maximum RTT values including both send/received:
Minimum number of packets including both send/received: Mean number of packets including both send/received: Maximum number of packets including both send/received:
Minimum receive window sizes including both send/received: Mean receive window sizes including both send/received: Maximum receive window sizes including both send/received:
*/
