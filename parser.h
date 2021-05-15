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

/*  Creates a header with RCODE = 4, signifying unimplemented request   */
dns_header_t *create_error_header(int id);

/*  Creates a binary DNS packet from the provided DNS message. Inverse of parse_packet()    
    Does not use message compression                                                        */                               
dns_packet_t *create_packet(message_t *msg);

/*  Creates and a byte sequence representing the given header.  */
uint8_t *create_header_sequence(dns_header_t *header);

/*  Creates a byte sequence representing the given resource record. Sets total_size to size of 
    byte sequence   */
uint8_t *create_RR_sequence(RR_t *RR, int *total_size);

/*  Creates a byte sequence representing the given question. Sets total_size to size of byte 
    sequence    */
uint8_t *create_question_sequence(question_t *question, int *total_size);

/*  Creates a byte sequence representing the given string (domain name). Uses the label format, 
    where a length octet precedes each label. Sets total_size to size of byte sequence    */
uint8_t *create_name_sequence(char *name, int *total_size);

/*  Prints information about a DNS record - for testing purposes    */
void print_message(message_t *message);

/*  Frees a packet  */
void free_packet(dns_packet_t *packet);

/*  Frees an array of pointers to questions   */
void free_question_array(question_t **array, int num_items);

/*  Frees an array of pointers to RRs   */
void free_RR_array(RR_t **array, int num_items);

/*  Frees a message */
void free_message(message_t *msg);

#endif