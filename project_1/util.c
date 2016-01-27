
/*******************************************************************************
 * util.c
 * Description: util program
 * CSC 361
 * Instructor: Kui Wu
 ******************************************************************************/
#define DEBUG 3

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <regex.h>
#include <stdbool.h>
#include <assert.h>

#ifdef DEBUG
   #define DEBUG_PRINT(x) printf x
#else
   #define DEBUG_PRINT(x) do {} while (0)
#endif

#define MAX_ERROR_MSG 0x1000

/* ------------
* util.c: used by client.c and server.c 
* ---------------*/
/*
int writen(int sd, char *ptr, int size);
int readn(int sd, char *ptr, int size);

/// write "size" bytes of "ptr" to "sd" /

int writen(int sd, char *ptr, int size) {
    int no_left, no_written;

    no_left = size; 
    while (no_left > 0)
    {
       no_written = write(sd, ptr, no_left);
       if (no_written <=0)
            return(no_written);
       no_left -= no_written;
       ptr += no_written;
    }
    return(size - no_left);
}

/// read "size bytes from "sd" to "ptr" /

int readn(int sd, char *ptr, int size) {
   int no_left, no_read;
   no_left = size;
   while (no_left >0)
   {
      no_read = read(sd, ptr, no_left);
      if (no_read <0)
         return(no_read);
      if (no_read ==0)
         break;
      no_left -= no_read;
      ptr += no_read;
    }
   return(size - no_left);
}*/

static int compile_regex (regex_t * r, const char * regex_text)
{
   int status = regcomp (r, regex_text, REG_EXTENDED|REG_NEWLINE);
      if (status != 0) {
   char error_message[MAX_ERROR_MSG];
   regerror (status, r, error_message, MAX_ERROR_MSG);
            printf ("Regex error compiling '%s': %s\n",
                         regex_text, error_message);
            return 1;
      }
      return 0;
}

/*
   Match the string in "to_match" against the compiled regular
   expression in "r".
 */

static int match_regex (regex_t * r, const char * to_match, char ** matches) {
      /* "P" is a pointer into the string which points to the end of the
          previous match. */
      const char * p = to_match;
      /* "N_matches" is the maximum number of matches allowed. */
      const int n_matches = 10;
      /* "M" contains the matches found. */
      regmatch_t m[n_matches];

      while (1) {
            int i = 0;
            int nomatch = regexec (r, p, n_matches, m, 0);
            if (nomatch) {
                  printf ("No more matches.\n");
                  return nomatch;
            }
            for (i = 0; i < n_matches; i++) {
                  int start;
                  int finish;
                  if (m[i].rm_so == -1) {
                        break;
                  }
                  start = m[i].rm_so + (p - to_match);
                  finish = m[i].rm_eo + (p - to_match);
                  if (i == 0) {
                        printf ("$& is ");
                  }
                  else {
                        printf ("$%d is ", i);
                  }
                  printf ("'%.*s' (bytes %d:%d)\n", (finish - start),
                              to_match + start, start, finish);
            }
            p += m[0].rm_eo;
      }
      return 0;
}