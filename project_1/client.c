/*******************************************************************************
 * client.c
 * Description: HTTP client program
 * CSC 361
 * Instructor: Kui Wu
 ******************************************************************************/

#include "util.h"

void perform_http(int sockid, char *identifier, char* uri);

int open_connection(char *hostname, int port);

int main(int argc, char* argv[]);

/*******************************************************************************
 * Main() routine
 * three main task will be excuted:
 * accept the input URI and parse it into fragments for further operation
 * open socket connection with specified sockid ID
 * use the socket id to connect sopecified server
 * don't forget to handle errors
 ******************************************************************************/

//main(int argc, char *argv)
int main(int argc, char* argv[]) {
    char uri[MAX_STR_LEN];
    bzero( uri, MAX_STR_LEN);
    if(argc==1) {
        char tmp [] = //"http://cnn.com/index.html"; 
                        "http://localhost:9898/index.html";
        memcpy(uri, tmp, sizeof(tmp));
    } else if (argc==2) {
        strcpy(uri, argv[1]);
        //memcpy(uri, argv[1], sizeof(argv[1]));
    } else {
        return 0;
    }
    char hostname[MAX_STR_LEN];
    char identifier[MAX_STR_LEN];
    int sockid, port;
    DEBUG_PRINT(("Open URI:  "));
    //scanf("%s", uri);
    int parser_exit_code = parse_URI(uri, hostname, &port, identifier);
    
    
    assert(parser_exit_code!=false);
    DEBUG_PRINT(("URI Parser Finished with Code: %d\n", parser_exit_code ));
    DEBUG_PRINT(("hostname: '%s', port: '%d', identifier: '%s'\n", 
      hostname, port, identifier));
    
    sockid = open_connection(hostname, port);
    DEBUG_PRINT(("\nopen_connection(hostname, port) returned a sockid: '%d'\n", sockid));
    
    perform_http(sockid, identifier, uri);
    
    return 0;
}


/*******************************************************************************
 * connect to a HTTP server using hostname and port, and get the resource
 * specified by identifier
 * 
 * @param (int) sockid
 * @param (char*) identifier
 * @return void
 ******************************************************************************/
void perform_http(int sockid, char* identifier, char* uri) {
    int i = 1;
  
    char request_buffer[MAX_STR_LEN];
    char receive_buffer[MAX_RES_LEN];
    
    // write zero-valued bytes to sendline/recvline
    bzero( request_buffer, MAX_STR_LEN);
    bzero( receive_buffer, MAX_RES_LEN);
    
    sprintf(request_buffer, "GET %s HTTP/1.0\r\n\r\n", uri);

    printf("---Request begin---\n%s---Request end---\nHTTP request sent, awaiting response...\n\n", request_buffer);
     
    write(sockid,request_buffer,strlen(request_buffer)+1);
    
    i = read(sockid,receive_buffer,MAX_RES_LEN);
    
    split_sequence(receive_buffer, "\r\n\r\n");
    int breakpoint = strlen(receive_buffer);
    
    
    
    printf("---Response header ---\n%s\n",receive_buffer);
    
    printf("\n--- Response body ---\n%s",&receive_buffer[breakpoint + strlen("\r\n\r\n")]);
    
    while(i > 0) {
      i = read(sockid,receive_buffer,MAX_RES_LEN);
      printf("%s", receive_buffer);
    }
    
    close(sockid);
}

/*******************************************************************************
 * open_conn() routine. It connects to a remote server on a specified port.
 *
 * @param (char*) hostname
 * @param (int) port
 * @return void
 ******************************************************************************/

int open_connection(char *hostname, int port) {
  int socket_id;
  struct hostent        *he;
  struct sockaddr_in  server;
  bzero(&server,sizeof(server));

  /* resolve hostname */
  // TODO: USE getaddrinfo INSTEAD / gethostbyname is deprecated
  if ( (he = gethostbyname(hostname) ) == NULL ) {
      exit(1); /* error */
  }

  /* copy the network address to sockaddr_in structure */
  memcpy(&server.sin_addr, he->h_addr_list[0], he->h_length);
  //DEBUG_PRINT(("\n\t[%s]", server.sin_addr));
  
  socket_id=socket(AF_INET,SOCK_STREAM,0);
  server.sin_family = AF_INET;
  server.sin_port = htons(port);
  
  int connection_code = connect(socket_id, (struct sockaddr *)&server, sizeof(server) );
  
  
  DEBUG_PRINT(("\nAttemting Connection: %s", (connection_code==0)?("OK"):("Failed")));
  
  DEBUG_PRINT(("\n\tcode=%d", connection_code));
  
  return socket_id;
}

