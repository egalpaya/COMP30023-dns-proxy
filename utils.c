/*************************************************************************************************/           
/*  COMP30023 Assignment 2                                                                       */
/*  Eishitha Galpayage Don                                                                       */
/*  993413                                                                                       */
/*  Various Utility Functions and Structures                                                     */
/*************************************************************************************************/
#include <time.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

#define TIMESTAMP_MAX_LEN 80

/*  Writes the current timestamp to the given string buffer */
void get_timestamp(char *str){

    time_t raw_time;
    struct tm *info;

    time(&raw_time);
    info = localtime(&raw_time);
    strftime(str, TIMESTAMP_MAX_LEN, "%FT%T%z ", info);
}

/*  Writes a string to the log, prepended by a timestamp    */
void write_log(char *str){

    char entry[TIMESTAMP_MAX_LEN+strlen(str)+1];
    get_timestamp(entry);
    strcat(entry, str);

    FILE *log = fopen("dns_svr.log", "a");
    fputs(entry, log);
    fflush(log);
    fclose(log);
}