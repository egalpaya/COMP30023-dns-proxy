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
#include <stdint.h>
#include <arpa/inet.h>
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

void parse_packet(unsigned char *packet, int size){
}

/*  Reads the header of the given packet, returning it as a struct  */
dns_header_t *read_header(dns_packet_t *packet){
    
    dns_header_t *header = (dns_header_t *)malloc(sizeof(dns_header_t));
    assert(header);

    memcpy(&(header->id), &(packet->data[0]), 2);
    header->id = htons(header->id);
    
    header->qr = packet->data[2] >> 7;
    
    header->opcode = (packet->data[2] >> 3) & 15;

    header->aa = (packet->data[2] >> 2) & 1;

    header->tc = (packet->data[2] >> 1) & 1;

    header->rd = packet->data[2] & 1;

    header->ra = packet->data[3] >> 7;

    header->rcode = packet->data[3] & 15;

    memcpy(&(header->qdcount), &(packet->data[4]), 2);
    header->qdcount = htons(header->qdcount);

    memcpy(&(header->ancount), &(packet->data[6]), 2);
    header->ancount = htons(header->ancount);

    memcpy(&(header->nscount), &(packet->data[8]), 2);
    header->nscount = htons(header->nscount);

    memcpy(&(header->arcount), &(packet->data[10]), 2);
    header->arcount = htons(header->arcount);

    return header;
}

/*  Reads a DNS packet from stdin and returns it as a struct    */
dns_packet_t *read_packet(){

    // read the two byte header
    uint16_t len;
    fread(&len, 1, 2, stdin);
    len = htons(len);
    
    // create struct and allocate memory
    dns_packet_t *packet = (dns_packet_t *)malloc(sizeof(dns_packet_t));
    assert(packet);
    packet->len = len;
    packet->data = (uint8_t *)malloc(sizeof(uint8_t)*len);
    assert(packet->data);
    
    // read in bytes from stream
    for (int i = 0; i < len; i++){
        fread(&packet->data[i], 1, 1, stdin);
    }

    return packet;
}

int main(int argc, char **argv){
    
    dns_packet_t *packet = read_packet();
    dns_header_t *header = read_header(packet);
    printf("id = %d, query = %d, opcode = %d, recursion = %d\n", header->id, header->qr, header->opcode, header->rd);

    return 0;
}
                                                                           