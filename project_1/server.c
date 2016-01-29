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
    atexit (cleanExit);
    
    int port;
    int option = 1;
    char ident[MAX_STR_LEN];
    
    // Process CMD Line Args [BEGIN]
    ////////////////////////////////////////////////////////////////////////////
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
    ////////////////////////////////////////////////////////////////////////////
    // Process CMD Line Args [END]
    
        
    // Setup Socket [BEGIN]
    ////////////////////////////////////////////////////////////////////////////
    char str[MAX_STR_LEN];
    int listen_fd, comm_fd;
 
    struct sockaddr_in servaddr;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    bzero( &servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htons(INADDR_ANY);
    servaddr.sin_port = htons(port);
    
    // tells kernal to force reuse of the address preventing binding problems
    setsockopt(listen_fd,SOL_SOCKET,SO_REUSEADDR,&option,sizeof(int));
 
    bind(listen_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));
 
    listen(listen_fd, 10);
 
    comm_fd = accept(listen_fd, (struct sockaddr*) NULL, NULL);
    
    bzero( str, MAX_STR_LEN);
    read(comm_fd,str,MAX_STR_LEN);
    ////////////////////////////////////////////////////////////////////////////
    // Setup Socket [END]

    printf("Processing Request - %s",str);
     
    perform_http(comm_fd, str, ident);
    cleanExit();
}

/*******************************************************************************
 *
 * cleans up opened sockets when killed by a signal.
 *
 ******************************************************************************/

void cleanExit() {
    printf("Exiting");
    exit(0);
}

/*******************************************************************************
 *
 * Accepts a request from "sockid" and sends a response to "sockid".
 *
 ******************************************************************************/
int perform_http(int sockid, char * request, char * identifier) {
    DEBUG_PRINT(("\nparse_http_header: ident: [%s]", identifier));
    int code = 0;

    char response[MAX_STR_LEN];
    
    strcpy(response, request);
    
    
    code = parse_http_header(response, identifier );
    DEBUG_PRINT(("\nCODE[%d]", code));
    
    char * data = 0;
    FILE *file;
    long length = 0;
    
    switch (code) {
        case 200:
            
            file = fopen(identifier, "r");
            if (file)
            {
                fseek (file, 0, SEEK_END);
                length = ftell (file);
                fseek (file, 0, SEEK_SET);
                data = malloc (length);
                if (data)
                {
                    fread (data, 1, length, file);
                }
                fclose (file);
            }
            
            sprintf(response, "HTTP/1.0 200 OK\r\n\r\n%s", data);
        break;
        case 404:
            strcpy(response, "HTTP/1.0 404 Not Found\r\n\r\n");
        break;
        case 501:
        default:
            strcpy(response, "HTTP/1.0 501 Not Implemented.\r\n\r\n");
        break;
    }
    
    write(sockid, response, MAX_STR_LEN);

}



/*******************************************************************************
 *
 * Note: intentional sideaffect ident expanded to full path
 *
 ******************************************************************************/

int parse_http_header(char * data, char * ident) {
    
    char hostname[MAX_STR_LEN];
    char identifier[MAX_STR_LEN];
    char uri[MAX_STR_LEN];
    int port;
    
    DEBUG_PRINT(("\nparse_http_header: ident: [%s]", ident));
    
    
    char * token; 
    printf("DATA[%s]", data);
    token = strtok(data, "\n\r ");
    if(token==NULL) return 5;
    
    printf("TOKEN[%s]", token);
    if(strcmp("GET",token) != 0) {
        return 3;
    }
    
    
    token = strtok(NULL, "\n\r ");
    int parser_exit_code = parse_URI(token, hostname, &port, identifier);
    //if(parser_exit_code == 0) {
    //    DEBUG_PRINT(("\n\nParser Failed\n"));
    //    return 1;
    //}

    char tmp[MAX_STR_LEN];
    sprintf(tmp,"%s%s", ident, identifier);
    DEBUG_PRINT(("file_path: [%s]",tmp));
    strcpy(ident, tmp);
    if( access( tmp, F_OK ) == -1 ) return 404;
    
    
    token = strtok(NULL, "\n\r ");
    DEBUG_PRINT(("token: [%s]", token));
    if(strcmp("HTTP/1.0", token) != 0) {
        return 2;
    }
    
    
    return 200;
}





