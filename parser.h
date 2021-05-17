/*************************************************************************************************/           
/*  COMP30023 Assignment 2                                                                       */
/*  Eishitha Galpayage Don                                                                       */
/*  993413                                                                                       */
/*  Functions to parse and create DNS packets                                                    */
/*************************************************************************************************/
#ifndef PARSER_H
#define PARSER_H

#include "utils.h"

/*  Reads a DNS packet from the given fd and returns it as a struct    */
packet_t *read_packet(int fd);

/*  Parses the given binary packet and returns a human-readable message struct  */
message_t *parse_packet(packet_t *packet);

/*  Reads a section of a DNS packet (Questions/RRs), given the number of items (individual
    questions/RRs) and a function to extract it. Returns an array of pointers to each item  */
void *read_section(packet_t *packet, uint16_t *offset, int num_items, 
                    void *(*read_field)(packet_t *, uint16_t *));

/*  Reads the header of the given packet, returning it as a struct  */
header_t *read_header(packet_t *packet);

/*  Reads a question section of the given packet at the given offset, returning it as a struct  */
void *read_question(packet_t *packet, uint16_t *offset);

/*  Reads a resource record of the given packet at the given offset, returning it as a struct   */
void *read_RR(packet_t *packet, uint16_t *offset);

/*  Reads a domain name encoded with labels (RFC1035 4.1.2.) into dest string   */
void read_domain_name(packet_t *packet, uint16_t *offset, char *dest);

/*  Copies n bytes (as ints) from the network order packet to host order message field (dest), 
    incrementing the offset by n.  */
void cpy_int_ntoh(packet_t *packet, uint16_t *offset, int n, void *dest);

/*  Creates a binary DNS packet from the provided DNS message. Inverse of parse_packet().    
    Does not use message compression    */                               
packet_t *create_packet(message_t *msg);

/*  Concatenates the bytes in the given array, writing to the dest array at the offset    */
void concat_section(uint8_t **array, int *sizes, int num_items, uint16_t *offset, uint8_t *dest);

/*  Populates an array of byte sequences, with each entry representing a section (question/RR) 
    of the DNS message. The sizes array will be populated with the number of bytes in each entry. 
    A function is passed in, either create_question_sequence() or create_RR_sequence(), which 
    does the work of converting the human readable section to bytes. Also updates len to reflect
    size of sequence.   */
void create_section_sequence(uint8_t **array, int *sizes, int num_fields, void **section,
                            uint16_t *len, uint8_t *(*create_field_sequence)(void *, int *));

/*  Creates a byte sequence representing the given header.  */
uint8_t *create_header_sequence(header_t *header);

/*  Creates a byte sequence representing the given resource record. Sets total_size to size of 
    byte sequence   */
uint8_t *create_RR_sequence(void *RR_ptr, int *total_size);

/*  Creates a byte sequence representing the given question. Sets total_size to size of byte 
    sequence    */
uint8_t *create_question_sequence(void *question_ptr, int *total_size);

/*  Creates a byte sequence representing the given string (domain name). Uses the label format, 
    where a length octet precedes each label. Sets total_size to size of byte sequence    */
uint8_t *create_name_sequence(char *name, int *total_size);

/*  Copies n bytes (as ints) from the host order src to network order dest, 
    incrementing the offset by n.  */
void cpy_int_hton(void *src, uint16_t *offset, int n, uint8_t *dest);

/*  Frees a packet  */
void free_packet(packet_t *packet);

/*  Frees an array of pointers  */
void free_array(void **array, int num_items);

/*  Frees an array of pointers to RRs   */
void free_RR_array(RR_t **array, int num_items);

/*  Frees a message */
void free_message(message_t *msg);

/*  Prints information about a DNS record - for testing purposes    */
void print_message(message_t *message);

#endif