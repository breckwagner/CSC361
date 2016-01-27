/*******************************************************************************
 * client.c
 * Description: HTTP client program
 * CSC 361
 * Instructor: Kui Wu
 ******************************************************************************/

#include "util.c"

#include "netdb.h"



/* define maximal string and reply length, this is just an example.*/
/* MAX_RES_LEN should be defined larger (e.g. 4096) in real testing. */
#define MAX_STR_LEN 120
#define MAX_RES_LEN 120

int parse_URI(char *uri, char *hostname, int *port, char *identifier);

void perform_http(int sockid, char *identifier);

int open_connection(char *hostname, int port);

int main(int argc, char ** argv);


/*******************************************************************************
 * Main() routine
 * three main task will be excuted:
 * accept the input URI and parse it into fragments for further operation
 * open socket connection with specified sockid ID
 * use the socket id to connect sopecified server
 * don't forget to handle errors
 ******************************************************************************/

//main(int argc, char *argv)
int main(int argc, char ** argv) {
    char uri[MAX_STR_LEN] = "http://google.com/index.html";
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
    DEBUG_PRINT(("open_connection(hostname, port) returned a sockid: '%d'\n", sockid));
    
    perform_http(sockid, identifier);
    
    return 0;
}

/*------ Parse an "uri" into "hostname" and resource "identifier" --------*/

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
        start = m[i].rm_so + (p - uri);
        finish = m[i].rm_eo + (p - uri);
        
        switch(i) {
          case 0: 
            DEBUG_PRINT(("\nParsing: "));
          break;
          case 1: 
            DEBUG_PRINT(("\tParsed 'protocol': "));
          break;
          case 2: 
            DEBUG_PRINT(("\tParsed 'hostname': "));
            memcpy(hostname, &uri[start], (finish - start)); 
          break;
          case 3: 
            DEBUG_PRINT(("\tParsed 'port': "));
            char port_copy[5];
            memcpy(port_copy, &uri[start], (finish - start)); 
            *port = (finish - start > 0)?(atoi(port_copy)):(80); 
          break;
          case 4: 
            DEBUG_PRINT(("\tParsed 'identifier': "));
            memcpy(identifier, &uri[start], (finish - start)); 
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
    char sendline[100];
    char recvline[100];
         
    while(true) {
        // write zero-valued bytes to sendline/recvline
        bzero( sendline, 100);
        bzero( recvline, 100);
        
        
        fgets(sendline,100,stdin); /*stdin = 0 , for standard input */
         
        write(sockid,sendline,strlen(sendline)+1);
        read(sockid,recvline,100);
        printf("%s",recvline);
    }
    close(sockid);
}

/*******************************************************************************
 *
 * open_conn() routine. It connects to a remote server on a specified port.
 *
 ******************************************************************************/

int open_connection(char *hostname, int port) {
  int sockfd;
  
  struct sockaddr_in server_addr;
  struct hostent *server_ent;
  server_ent= gethostbyname(hostname);
  memcpy(&server_addr.sin_addr, server_ent->h_addr, server_ent->h_length);
  
  
  sockfd=socket(AF_INET,SOCK_STREAM,0);
  bzero(&server_addr,sizeof(server_addr));
  server_addr.sin_family=AF_INET;
  server_addr.sin_port=htons(port);
   
  inet_pton(AF_INET,gethostbyname(hostname),&(server_addr.sin_addr));
   
  connect(sockfd,(struct sockaddr *)&server_addr,sizeof(server_addr));

  return sockfd;
}
