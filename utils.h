/*************************************************************************************************/           
/*  COMP30023 Assignment 2                                                                       */
/*  Eishitha Galpayage Don                                                                       */
/*  993413                                                                                       */
/*  Various Utility Functions and Structures                                                     */
/*************************************************************************************************/
#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

#define MAX_DNAME_CHARS 255

typedef struct dns_packet dns_packet_t;
typedef struct dns_header dns_header_t;
typedef struct question question_t;
typedef struct RR RR_t;
typedef struct message message_t;

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

struct question {
    char qname[MAX_DNAME_CHARS];
    uint16_t qtype;
    uint16_t qclass;
};

struct RR {
    char name[MAX_DNAME_CHARS];
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    uint8_t *rdata;
};

struct message {
    dns_header_t *header;
    question_t **questions;
    RR_t **answers;
    RR_t **authorities;
    RR_t **additional;
};



/*  Writes the current timestamp to the given string buffer */
void get_timestamp(char *str);

/*  Writes a string to the log, prepended by a timestamp    */
void write_log(char *str);





#endif
