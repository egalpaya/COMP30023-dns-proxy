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


/*  Writes the current timestamp to the given string buffer */
void get_current_timestamp(char *str){

    time_t raw_time;
    time(&raw_time);

    get_timestamp(str, raw_time);
}

/*  Writes the given time to str, formatted as a timestamp  */
void get_timestamp(char *str, time_t time){

    struct tm *time_info;
    time_info = localtime(&time);
    strftime(str, MAX_TIMESTAMP_LEN, "%FT%T%z ", time_info);
}   

/*  Writes a string to the log, prepended by a timestamp    */
void write_log(char *str){

    char entry[MAX_TIMESTAMP_LEN+strlen(str)+1];
    get_current_timestamp(entry);
    strcat(entry, str);

    FILE *log = fopen("dns_svr.log", "a");
    fputs(entry, log);
    fflush(log);
    fclose(log);
}

/*  Removes trailing dot in a string (for fully specified domain names) */
void remove_trailing_dot(char *str){

    char *last_dot = strrchr(str, '.');
    if (last_dot){
        *last_dot = '\0';
    }
}