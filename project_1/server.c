/*******************************************************************************
 * server.c
 * Description: HTTP server program
 * CSC 361
 * Instructor: Kui Wu
 ******************************************************************************/

#include "util.h"

void cleanExit();

int perform_http(int sockid, char * request, char * identifier);

int parse_http_header(char * data, char * ident);

int main(int argc, char* argv[]);

/*******************************************************************************
 * tasks for main
 * generate socket and get socket id,
 * max number of connection is 3 (maximum length the queue of pending 
 * connections may grow to)
 * Accept request from client and generate new socket
 * Communicate with client and close new socket after done
 ******************************************************************************/

int main(int argc, char* argv[]) {
    int port;
    char ident[MAX_STR_LEN];
    if(argc==1) {
        port = SERVER_PORT_ID;
    } else if (argc==3) {
        port = atoi(argv[1]);
        strcpy(ident, argv[2]);

    } else if (argc==2) {
        port = atoi(argv[1]);
    } else {
        DEBUG_PRINT(("Wrong number of Arguments: exiting"));
        return 0;
    }
        
    
    char str[MAX_STR_LEN];
    int listen_fd, comm_fd;
 
    struct sockaddr_in servaddr;
 
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
 
    bzero( &servaddr, sizeof(servaddr));
 
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htons(INADDR_ANY);
    servaddr.sin_port = htons(port);
 
    bind(listen_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));
 
    listen(listen_fd, 10);
 
    comm_fd = accept(listen_fd, (struct sockaddr*) NULL, NULL);
    
    bzero( str, MAX_STR_LEN);
    read(comm_fd,str,MAX_STR_LEN);
    

    
 
    //while (true) {
 
        
 
        
 
        printf("Processing Request - %s",str);
 
        perform_http(comm_fd, str, ident);
        
        //write(comm_fd, str, strlen(str)+1);
 
    //}
    

    
    
    /*
    int newsockid; // return value of the accept() call 

    while (1) {
      close(newsockid);
    }*/
    
    cleanExit();
}

/*******************************************************************************
 *
 * cleans up opened sockets when killed by a signal.
 *
 ******************************************************************************/

void cleanExit() {
    exit(0);
}

/*******************************************************************************
 *
 * Accepts a request from "sockid" and sends a response to "sockid".
 *
 ******************************************************************************/
int perform_http(int sockid, char * request, char * identifier) {
    int code = 0;
    /*
    int c;
    FILE *file;
    file = fopen(, "r");
    if (file) {
        while ((c = getc(file)) != EOF)
            putchar(c);
        fclose(file);
    }
    */
    char response[MAX_STR_LEN];
    
    strcpy(response, request);
    
    
    code = parse_http_header(response, identifier);
    printf("CODE[%d]", code);
    char data[] = "This is an example file";
    
    switch (code) {
        case 200:
            //sprintf(response, "HTTP/1.0 200 OK\r\n\r\n%s", data);
            strcpy(response, "HTTP/1.0 501 Not Implemented.\r\n\r\n");
        break;
        case 404:
            sprintf(response, "HTTP/1.0 404 Not Found\r\n\r\n%s", data);
        break;
        case 501:
        case 0:
        default:
            strcpy(response, "HTTP/1.0 501 Not Implemented.\r\n\r\n");
        break;
    }
    
    write(sockid, response, MAX_STR_LEN);

}





int parse_http_header(char * data, char * ident) {
    char * result;
    char hostname[MAX_STR_LEN];
    char identifier[MAX_STR_LEN];
    char uri[MAX_STR_LEN];
    int port;
    
    
    char * token; 
    printf("DATA[%s]", data);
    token = strtok(data, "\n\r ");
    if(token==NULL) return 0;
    
    printf("TOKEN[%s]", token);
    //if(strcmp("GET",token) != 0) {
    //    return 501;
    //}
    
    /*
    //token = strtok(NULL, "\n\r ");
    int parser_exit_code = parse_URI(uri, hostname, &port, identifier);
    if(parser_exit_code != 0) return 501;
    
    if( access( ident, F_OK ) == -1 ) return 404;
    
    //token = strtok(NULL, "\n\r ");
    if(strcmp("HTTP/1.0", token) != 0) {
        return 501;
    }*/
    
    
    return 0;
}





