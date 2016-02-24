

#include <stdlib.h>
#include <string.h>

#define LINE_SEPERATOR_1 "++++++++++++++++++++++++++++++++++++++++"\
                         "++++++++++++++++++++++++++++++++++++++++"

#define LINE_SEPERATOR_2 "----------------------------------------"\
                         "----------------------------------------"
/**
 * Concatinates two strings
 * @see http://stackoverflow.com/q/8465006/
 */
 /*
char* concat(char *s1, char *s2) {
    size_t len1 = strlen(s1);
    size_t len2 = strlen(s2);
    char *result = malloc(len1+len2+1);//+1 for the zero-terminator
    //in real code you would check for errors in malloc here
    memcpy(result, s1, len1);
    memcpy(result+len1, s2, len2+1);//+1 to copy the null-terminator
    return result;
}
*/
