#ifndef UTIL_H_   /* Include guard */
#define UTIL_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <regex.h>
#include <stdbool.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

//#define DEBUG 3

#ifdef DEBUG
	#define DEBUG_PRINT(x) printf x
#else
	#define DEBUG_PRINT(x) do {} while (0)
#endif

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

#define SERVER_PORT_ID 9898
#define MAX_ERROR_MSG 0x1000
#define MAX_STR_LEN 4096
#define MAX_RES_LEN 4096


static int compile_regex (regex_t * r, const char * regex_text);

//static int match_regex (regex_t * r, const char * to_match, char ** matches);

int writen(int sd, char *ptr, int size);

int readn(int sd, char *ptr, int size);

int parse_URI(char *uri, char *hostname, int *port, char *identifier);

#endif