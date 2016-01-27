#define DEBUG 3

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




#ifdef DEBUG
	#define DEBUG_PRINT(x) printf x
#else
	#define DEBUG_PRINT(x) do {} while (0)
#endif

#define MAX_ERROR_MSG 0x1000

/* ------------
* util.c: used by client.c and server.c 
* ---------------*/

//int writen(int sd, char *ptr, int size);

//int readn(int sd, char *ptr, int size);

static int compile_regex (regex_t * r, const char * regex_text);

static int match_regex (regex_t * r, const char * to_match, char ** matches);