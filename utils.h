/*************************************************************************************************/           
/*  COMP30023 Assignment 2                                                                       */
/*  Eishitha Galpayage Don                                                                       */
/*  993413                                                                                       */
/*  Various Utility Functions and Structures                                                     */
/*************************************************************************************************/
#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <time.h>

#define MAX_DNAME_CHARS 255
#define MAX_TIMESTAMP_LEN 80
#define MAX_LOG_ENTRY 1024

typedef struct packet packet_t;
typedef struct header header_t;
typedef struct question question_t;
typedef struct RR RR_t;
typedef struct message message_t;

struct packet {
    uint16_t len;
    uint8_t *data;
};

struct header {
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
    header_t *header;
    question_t **questions;
    RR_t **answers;
    RR_t **authorities;
    RR_t **additional;
};

/*  Writes the given time to str, formatted as a timestamp  */
void get_timestamp(char *str, time_t time);

/*  Writes the current timestamp to the given string buffer */
void get_current_timestamp(char *str);

/*  Writes a string to the log, prepended by a timestamp    */
void write_log(const char *str);

/*  Removes trailing dot in a string (for fully specified domain names) */
void remove_trailing_dot(char *str);

#endif
