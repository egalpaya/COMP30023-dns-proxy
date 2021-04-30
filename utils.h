/*************************************************************************************************/           
/*  COMP30023 Assignment 2                                                                       */
/*  Eishitha Galpayage Don                                                                       */
/*  993413                                                                                       */
/*  Various Utility Functions and Structures                                                     */
/*************************************************************************************************/
#ifndef UTILS_H
#define UTILS_H

typedef struct dns_packet dns_packet_t;
typedef struct dns_header dns_header_t;

struct dns_packet {
    uint16_t len;
    uint8_t *data;
};

struct dns_header {
    uint16_t id;
    uint8_t qr;
    uint8_t opcode;
    uint8_t aa;
    uint8_t tc;
    uint8_t rd;
    uint8_t ra;
    uint8_t rcode;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};











#endif
