/*************************************************************************************************/           
/*  COMP30023 Assignment 2                                                                       */
/*  Eishitha Galpayage Don                                                                       */
/*  993413                                                                                       */
/*  Functions to parse DNS packets                                                               */
/*************************************************************************************************/
#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include "utils.h"

/*  Copies n bytes (as ints) from the packet to dest, incrementing the offset   */
void cpy_int_field(dns_packet_t *packet, uint16_t *byte_offset, int n, void *dest);

/*  Reads a domain name encoded with labels (RFC1035 4.1.2.) into dest string   */
void read_domain_name(dns_packet_t *packet, uint16_t *byte_offset, char *dest);

/*  Reads a resource record of the given packet at the given offset, returning it as a struct   */
void *read_RR(dns_packet_t *packet, uint16_t *byte_offset);

/*  Reads a question section of the given packet at the given offset, returning it as a struct  */
void *read_question(dns_packet_t *packet, uint16_t *byte_offset);

/*  Reads the header of the given packet, returning it as a struct  */
dns_header_t *read_header(dns_packet_t *packet);

/*  Reads a DNS packet from the given fd and returns it as a struct    */
dns_packet_t *read_packet(int fd);

/*  Reads a section of a DNS packet (Questions/RRs), given the number of items (individual
    questions/RRs) and a function to extract it                                             */
void *read_section(dns_packet_t *packet, uint16_t *byte_offset, int num_items, 
                    void *(*read_field)(dns_packet_t *, uint16_t *));

/*  Parses the given binary packet and returns a human-readable message struct  */
message_t *parse_packet(dns_packet_t *packet);

/*  Prints information about a DNS record - for testing purposes    */
void print_message(message_t *message);

#endif