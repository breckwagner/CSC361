/*******************************************************************************
 * server.c
 * Description: HTTP server program
 * CSC 361
 * Instructor: Kui Wu
 ******************************************************************************/

#include "util.c"

#define MAX_STR_LEN 120         /* maximum string length */
#define SERVER_PORT_ID 9898     /* server port number */

void cleanExit();

/*******************************************************************************
 * tasks for main
 * generate socket and get socket id,
 * max number of connection is 3 (maximum length the queue of pending connections may grow to)
 * Accept request from client and generate new socket
 * Communicate with client and close new socket after done
 ******************************************************************************/

// main(int argc, char *argv) {
int main(int argc, char ** argv) {
    char str[100];
    int listen_fd, comm_fd;
 
    struct sockaddr_in servaddr;
 
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
 
    bzero( &servaddr, sizeof(servaddr));
 
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htons(INADDR_ANY);
    servaddr.sin_port = htons(SERVER_PORT_ID);
 
    bind(listen_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));
 
    listen(listen_fd, 10);
 
    comm_fd = accept(listen_fd, (struct sockaddr*) NULL, NULL);
 
    while (true) {
 
        bzero( str, 100);
 
        read(comm_fd,str,100);
 
        printf("Echoing back - %s",str);
 
        write(comm_fd, str, strlen(str)+1);
 
    }
    
    
    /*
    int newsockid; // return value of the accept() call 

    while (1) {
      close(newsockid);
    }*/
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
int perform_http(int sockid) {

}











