/*************************************************************************************************/           
/*  COMP30023 Assignment 2                                                                       */
/*  Eishitha Galpayage Don                                                                       */
/*  993413                                                                                       */
/*  Phase 1                                                                                      */
/*************************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <assert.h>

#define TIMESTAMP_MAX_LEN 80
#define INITIAL_PACKET_SIZE 4

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

void parse_packet();

int read_packet(unsigned char *packet, int size){

    int num_bytes = 0;

    while(fread(&packet[num_bytes], 1, 1, stdin)){
        if (++num_bytes == size){
            packet = (unsigned char *)realloc(packet, 2*size);
            assert(packet);
        }
    }

    return num_bytes;
}
int main(int argc, char **argv){
    
    int size = INITIAL_PACKET_SIZE;
    unsigned char *packet = (unsigned char *)malloc(sizeof(unsigned char)*size);
    assert(packet);

    int num_bytes = read_packet(packet, size);
    
    for (int i = 0; i < num_bytes; i++){
        printf("%x ", packet[i]);
    }
    printf("\n");

    return 0;
}
                                                                           