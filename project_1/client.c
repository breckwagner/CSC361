/*******************************************************************************
 * client.c
 * Description: HTTP client program
 * CSC 361
 * Instructor: Kui Wu
 ******************************************************************************/

#include "util.c"



/* define maximal string and reply length, this is just an example.*/
/* MAX_RES_LEN should be defined larger (e.g. 4096) in real testing. */
#define MAX_STR_LEN 4096
#define MAX_RES_LEN 4096

int parse_URI(char *uri, char *hostname, int *port, char *identifier);

void perform_http(int sockid, char *identifier);

int open_connection(char *hostname, int port);

int main(int argc, char * argv[]);

/*******************************************************************************
 * Main() routine
 * three main task will be excuted:
 * accept the input URI and parse it into fragments for further operation
 * open socket connection with specified sockid ID
 * use the socket id to connect sopecified server
 * don't forget to handle errors
 ******************************************************************************/

//main(int argc, char *argv)
int main(int argc, char * argv[]) {
    char uri[MAX_STR_LEN];
    bzero( uri, MAX_STR_LEN);
    if(argc==1) {
        char tmp [] = "http://google.com:80/index.html";
        memcpy(uri, tmp, sizeof(tmp));
    } else if (argc==2) {
        memcpy(uri, argv[1], sizeof(argv[1]));
    } else {
        return 0;
    }
    char hostname[MAX_STR_LEN];
    char identifier[MAX_STR_LEN];
    int sockid, port;
    printf("Open URI:  ");
    //scanf("%s", uri);
    int parser_exit_code = parse_URI(uri, hostname, &port, identifier);
    
    
    assert(parser_exit_code!=false);
    printf("URI Parser Finished with Code: %d\n", parser_exit_code );
    DEBUG_PRINT(("hostname: '%s', port: '%d', identifier: '%s'\n", 
      hostname, port, identifier));
    
    sockid = open_connection(hostname, port);
    DEBUG_PRINT(("\nopen_connection(hostname, port) returned a sockid: '%d'\n", sockid));
    
    perform_http(sockid, identifier);
    
    return 0;
}

/*******************************************************************************
 * connect to a HTTP server using hostname and port, and get the resource
 * specified by identifier
 * 
 * @param (char*) uri
 * @param (char*) hostname
 * @param (int*) port
 * @param (char*) identifier
 * @return (int) true (1) if successful and false (0)
 ******************************************************************************/
int parse_URI(char *uri, char *hostname, int *port, char *identifier) {
    regex_t r;
    const char * regex_text = 
        "([[:alpha:]]+)://([^/:]+):?([[:digit:]]*)/?([[:print:]]*)";
    compile_regex(& r, regex_text);
    
    const char * p = uri;
    char * ptr;
    /* "N_matches" is the maximum number of matches allowed. */
    const int n_matches = 5;
    /* "M" contains the matches found. */
    regmatch_t m[n_matches];
    
    while (1) {
      int i = 0;
      int nomatch = regexec (&r, p, n_matches, m, 0);
      if (nomatch) return nomatch;
      for (i = 0; i < n_matches; i++) {
        int start, finish;
        if (m[i].rm_so == -1) break;
        start = m[i].rm_so;// + (p - uri);
        finish = m[i].rm_eo;// + (p - uri);
        
        switch(i) {
          case 0: 
            DEBUG_PRINT(("\nParsing: "));
          break;
          case 1: 
            DEBUG_PRINT(("\tParsed 'protocol': "));
          break;
          case 2: 
            DEBUG_PRINT(("\tParsed 'hostname': "));
            memmove(hostname, &uri[start], (finish - start)); 
            hostname[(finish - start)] = '\0';
          break;
          case 3: 
            DEBUG_PRINT(("\tParsed 'port': "));
            char port_copy[5];
            memmove(port_copy, &uri[start], (finish - start)); 
            *port = (finish - start > 0)?(atoi(port_copy)):(80); 
          break;
          case 4: 
            DEBUG_PRINT(("\tParsed 'identifier': "));
            memmove(identifier, &uri[start], (finish - start)); 
            identifier[(finish - start)] = '\0';
          break;
          default: break;
        }
        
        DEBUG_PRINT(("'%.*s' (bytes %d:%d)\n", (finish - start),
        uri + start, start, finish));
      }
      p += m[0].rm_eo;
    }
    
    // Free the memory allocated to the pattern buffer
    regfree (& r);
    
    return true;
}

/*******************************************************************************
 * connect to a HTTP server using hostname and port, and get the resource
 * specified by identifier
 * 
 * @param (int) sockid
 * @param (char*) identifier
 * @return void
 ******************************************************************************/
void perform_http(int sockid, char *identifier) {
    char request_buffer[MAX_STR_LEN];
    char receive_buffer[MAX_RES_LEN];
    
    // write zero-valued bytes to sendline/recvline
    bzero( request_buffer, MAX_STR_LEN);
    bzero( receive_buffer, MAX_RES_LEN);
    
    sprintf(request_buffer, "GET /%s HTTP/1.0\r\n\r\n", identifier);

    printf("---Request begin---\n%s\n\n---Request end---\nHTTP request sent, awaiting response...\n\n", request_buffer);
     
    write(sockid,request_buffer,strlen(request_buffer)+1);

    read(sockid,receive_buffer,MAX_RES_LEN);
    
    printf("---Response header ---\n%s\n\n--- Response body ---",receive_buffer);
    close(sockid);
}

/*******************************************************************************
 *
 * open_conn() routine. It connects to a remote server on a specified port.
 *
 ******************************************************************************/

int open_connection(char *hostname, int port) {
  int socket_id;
  /*
  struct sockaddr_in server_addr;
  struct hostent *server_ent;
  server_ent= gethostbyname(hostname);
  printf("\nGetting Host by Name: %.*s",server_ent->h_length, server_ent->h_addr);
  
  
  
  memcpy(&server_addr.sin_addr, server_ent->h_addr, server_ent->h_length);
  
  
  sockfd=socket(AF_INET,SOCK_STREAM,0);
  
  
  //bzero(&server_addr,sizeof(server_addr));
  
  
  server_addr.sin_family=AF_INET;
  
  
  server_addr.sin_port=htons(port);
   
  //inet_pton(AF_INET,server_addr.sin_addr,&(server_addr.sin_addr));
  
    int connection_code = connect(sockfd,(struct sockaddr *)&server_addr,sizeof(server_addr));
   */
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
