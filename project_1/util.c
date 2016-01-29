
/*******************************************************************************
 * util.c
 * Description: util program
 * CSC 361
 * Instructor: Kui Wu
 ******************************************************************************/
//#define DEBUG 3



#include "util.h"


/* ------------
* util.c: used by client.c and server.c 
* ---------------*/
/*
int writen(int sd, char *ptr, int size);

int readn(int sd, char *ptr, int size);

static int compile_regex (regex_t * r, const char * regex_text);

static int match_regex (regex_t * r, const char * to_match, char ** matches);
*/
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
}


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

/*******************************************************************************
 * 
 *
 * @param (char *) string
 * @param (char *) delimiter
 * @return 0 on success -1 otherwise
 ******************************************************************************/
int split_sequence(char * string, char * delimiter) {
   char * ptr = string;
   int i = 0, j = 0;
   for(; ptr[i]!='\0'; i++) {
      if(ptr[i] == delimiter[j]) {
         j++;
      } else if(delimiter[j] == '\0') {
         while(j > 0) string[i - j--] = '\0';
      } else {
         i -= j;
         j = 0;
      }
   }
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
      DEBUG_PRINT(("\nStarting Parser: "));
      regex_t r;
      const char * regex_text = 
            "([[:alpha:]]+)://([^/:]+):?([[:digit:]]*)/?([[:print:]]*)";
            //"(^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(?([^#]*))?(#(.*))?)";

      compile_regex(& r, regex_text);
      
      const char * p = uri;
      char * ptr;
      /* "N_matches" is the maximum number of matches allowed. */
      const int n_matches = 5;
      /* "M" contains the matches found. */
      regmatch_t m[n_matches];
      
      DEBUG_PRINT(("\nParsing Ready: "));
      
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
