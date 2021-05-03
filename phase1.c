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
#include <unistd.h>
#include "utils.h"

#define TIMESTAMP_MAX_LEN 80
#define HEADER_LEN 12

/*  Copies n bytes (as ints) from the packet to dest, incrementing the offset   */
void cpy_int_field(dns_packet_t *packet, uint16_t *byte_offset, int n, void *dest){

    memcpy(dest, &(packet->data[*byte_offset]), n);

    if (n == 4){
        *(uint32_t *)dest = htonl(*(uint32_t *)dest);
    } else if (n == 2){
        *(uint16_t *)dest = htons(*(uint16_t *)dest);
    }

    *(byte_offset) += n;
}

/*  Reads a domain name encoded with labels (RFC1035 4.1.2.) into dest string   */
void read_domain_name(dns_packet_t *packet, uint16_t *byte_offset, char *dest){

    // sequentially write each label to dest string
    while (packet->data[*byte_offset] != 0){
        uint8_t len = packet->data[(*byte_offset)++];
        strncat(dest, (char *)&(packet->data[*byte_offset]), len);
        strcat(dest, ".");
        (*byte_offset) += len;
    }
    (*byte_offset)++;
}

/*  Reads a resource record of the given packet at the given offset, returning it as a struct   */
RR_t *read_RR(dns_packet_t *packet, uint16_t *byte_offset){

    RR_t *rr = (RR_t *)malloc(sizeof(RR_t));
    assert(rr);

    memset(rr->name, 0, MAX_DNAME_CHARS);

    if (packet->data[*byte_offset] >> 6 == 3){
        // message compression is used 
        uint16_t pointer; 
        cpy_int_field(packet, byte_offset, 2, &pointer);
        // remove 2 leading bits (which indicate compression)
        pointer = pointer & 16383;
        read_domain_name(packet, &pointer, rr->name);
    } else {
        read_domain_name(packet, byte_offset, rr->name);
    }

    // read in integer fields
    cpy_int_field(packet, byte_offset, 2, &(rr->type));
    cpy_int_field(packet, byte_offset, 2, &(rr->class));
    cpy_int_field(packet, byte_offset, 4, &(rr->ttl));
    cpy_int_field(packet, byte_offset, 2, &(rr->rdlength));

    // allocate memory and read rdata
    rr->rdata = (uint8_t *)malloc(sizeof(uint8_t)*(rr->rdlength));
    assert(rr->rdata);

    memcpy(rr->rdata, &(packet->data[*byte_offset]), rr->rdlength);
    (*byte_offset) += rr->rdlength;

    return rr;
}

/*  Reads a question section of the given packet at the given offset, returning it as a struct  */
question_t *read_question(dns_packet_t *packet, uint16_t *byte_offset){

    question_t *question = (question_t *)malloc(sizeof(question_t));
    assert(question);

    memset(question->qname, 0, MAX_DNAME_CHARS);

    read_domain_name(packet, byte_offset, question->qname);

    cpy_int_field(packet, byte_offset, 2, &(question->qtype));
    cpy_int_field(packet, byte_offset, 2, &(question->qclass));

    return question;
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

/*  Reads a DNS packet from the given fd and returns it as a struct    */
dns_packet_t *read_packet(int fd){

    // read the two byte header
    uint16_t len;
    assert(read(fd, &len, 2) == 2);
    len = htons(len);
    
    // create struct and allocate memory
    dns_packet_t *packet = (dns_packet_t *)malloc(sizeof(dns_packet_t));
    assert(packet);
    packet->len = len;
    packet->data = (uint8_t *)malloc(sizeof(uint8_t)*len);
    assert(packet->data);
    
    // read in bytes from stream
    for (int i = 0; i < len; i++){
        assert(read(fd, &packet->data[i], 1) == 1);
    }

    return packet;
}

void *read_field(dns_packet_t *packet, uint16_t *byte_offset, int num_items, void *(*fun)(dns_packet_t *, uint16_t *)){

    void **fields = NULL;

    if (num_items){
        void **fields = (void **)malloc(sizeof(void *)*num_items);
        assert(fields);

        for (int i = 0; i < num_items; i++){
            fields[i] = fun(packet, byte_offset);
        }
    }

    return fields;
}

/*  Parses the given binary packet and returns a human-readable message struct  */
message_t *parse_packet(dns_packet_t *packet){

    message_t *message = (message_t *)malloc(sizeof(message_t));
    assert(message);

    message->header = read_header(packet);
    uint16_t byte_offset = HEADER_LEN;

    if (message->header->qdcount){
        message->questions = (question_t **)malloc(sizeof(question_t *)*(message->header->qdcount));
        assert(message->questions);

        for (int i = 0; i < message->header->qdcount; i++){
            message->questions[i] = read_question(packet, &byte_offset);
        }
    } else {
        message->questions = NULL;
    }

    if (message->header->ancount){
        message->answers = (RR_t **)malloc(sizeof(RR_t *)*(message->header->ancount));
        assert(message->answers);

        for (int i = 0; i < message->header->ancount; i++){
            message->answers[i] = read_RR(packet, &byte_offset);
        }
    } else {
        message->answers = NULL;
    }

    if (message->header->nscount){
        message->authorities = (RR_t **)malloc(sizeof(RR_t *)*(message->header->nscount));
        assert(message->authorities);

        for (int i = 0; i < message->header->nscount; i++){
            message->authorities[i] = read_RR(packet, &byte_offset);
        }
    } else {
        message->authorities = NULL;
    }

    if (message->header->arcount){
        message->additional = (RR_t **)malloc(sizeof(RR_t *)*(message->header->arcount));
        assert(message->additional);

        for (int i = 0; i < message->header->arcount; i++){
            message->additional[i] = read_RR(packet, &byte_offset);
        }
    } else {
        message->additional = NULL;
    }

    return message;
}

void print_message(message_t *message){

    printf("HEADER: id = %d, qr = %d, opcode = %d, aa = %d, tc = %d, rd = %d, ra = %d, rcode = %d, qdcount = %d, ancount = %d, nscount = %d, arcount = %d\n", message->header->id, message->header->qr, message->header->opcode, message->header->aa, message->header->tc, message->header->rd, message->header->ra, message->header->rcode, message->header->qdcount, message->header->ancount,message->header->nscount, message->header->arcount);

    for (int i = 0; i < message->header->qdcount; i++){
        printf("QUESTION: qname = %s, qtype = %d, qclass = %d\n", message->questions[i]->qname, message->questions[i]->qtype, message->questions[i]->qclass);
    }

    for (int i = 0; i < message->header->ancount; i++){
        printf("RR Answers: name: %s, type = %d, class = %d, ttl = %d, rdlength = %d\n", message->answers[i]->name, message->answers[i]->type, message->answers[i]->class, message->answers[i]->ttl, message->answers[i]->rdlength);
    }

    for (int i = 0; i < message->header->nscount; i++){
        printf("RR Authority: name: %s, type = %d, class = %d, ttl = %d, rdlength = %d\n", message->authorities[i]->name, message->authorities[i]->type, message->authorities[i]->class, message->authorities[i]->ttl, message->authorities[i]->rdlength);
    }

    for (int i = 0; i < message->header->arcount; i++){
        printf("RR Additional: name: %s, type = %d, class = %d, ttl = %d, rdlength = %d\n", message->additional[i]->name, message->additional[i]->type, message->additional[i]->class, message->additional[i]->ttl, message->additional[i]->rdlength);
    }
}

int main(int argc, char **argv){
    
    dns_packet_t *packet = read_packet(STDIN_FILENO);
    message_t *message = parse_packet(packet);

    print_message(message);

    return 0;
}
                                                                           