/*************************************************************************************************/           
/*  COMP30023 Assignment 2                                                                       */
/*  Eishitha Galpayage Don                                                                       */
/*  993413                                                                                       */
/*  Functions to parse DNS packets                                                               */
/*************************************************************************************************/
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include "parser.h"

#define HEADER_LEN 12   // includes 2 byte message length

/*  Copies n bytes (as ints) from the packet to dest, incrementing the offset   */
void cpy_int_field(dns_packet_t *packet, uint16_t *byte_offset, int n, void *dest){

    memcpy(dest, &(packet->data[*byte_offset]), n);

    if (n == 4){
        *(uint32_t *)dest = ntohl(*(uint32_t *)dest);
    } else if (n == 2){
        *(uint16_t *)dest = ntohs(*(uint16_t *)dest);
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
void *read_RR(dns_packet_t *packet, uint16_t *byte_offset){

    RR_t *rr = (RR_t *)malloc(sizeof(RR_t));
    assert(rr);

    memset(rr->name, 0, MAX_DNAME_CHARS);

    // Check if message compression is used (2 leading bits of byte are both 1)
    // Note: 3 = 0b00000011
    if (packet->data[*byte_offset] >> 6 == 3){

        uint16_t pointer; 
        cpy_int_field(packet, byte_offset, 2, &pointer);

        // remove 2 leading bits (NOTE 16383 = 0b0011111111111111)
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
void *read_question(dns_packet_t *packet, uint16_t *byte_offset){

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

    // The data starts at byte 2 (first 2 bytes are length)
    memcpy(&(header->id), &(packet->data[2]), 2);
    header->id = ntohs(header->id);
    
    // byte 4 bit 0
    header->qr = packet->data[4] >> 7;
    // byte 4 bits 1-4 (15 = 0b00001111)
    header->opcode = (packet->data[4] >> 3) & 15;
    // byte 4 bit 5
    header->aa = (packet->data[4] >> 2) & 1;
    // byte 4 bit 6
    header->tc = (packet->data[4] >> 1) & 1;
    // byte 4 bit 7
    header->rd = packet->data[4] & 1;
    // byte 5 bit 0
    header->ra = packet->data[5] >> 7;
    // byte 5 bits 4-7 (15 = 0b00001111)
    header->rcode = packet->data[5] & 15;

    memcpy(&(header->qdcount), &(packet->data[6]), 2);
    header->qdcount = ntohs(header->qdcount);

    memcpy(&(header->ancount), &(packet->data[8]), 2);
    header->ancount = ntohs(header->ancount);

    memcpy(&(header->nscount), &(packet->data[10]), 2);
    header->nscount = ntohs(header->nscount);

    memcpy(&(header->arcount), &(packet->data[12]), 2);
    header->arcount = ntohs(header->arcount);

    return header;
}

/*  Reads a DNS packet from the given fd and returns it as a struct    */
dns_packet_t *read_packet(int fd){

    // read the two byte header
    uint16_t len_n;
    assert(read(fd, &len_n, 2) == 2);
    uint16_t len_h = ntohs(len_n);
    
    // create struct and allocate memory
    dns_packet_t *packet = (dns_packet_t *)malloc(sizeof(dns_packet_t));
    assert(packet);
    packet->len = len_h;
    // we will include the 2 bytes defining message length
    packet->data = (uint8_t *)malloc(sizeof(uint8_t)*(len_h+2));
    assert(packet->data); 

    // copy the length bytes
    memcpy(&(packet->data[0]), &len_n, 2);

    // read in payload bytes from stream (indexing is offset by 2)
    for (int i = 0; i < len_h; i++){
        if ((read(fd, &packet->data[i+2], 1)) != 1){
            fprintf(stderr, "error reading packet\n");
            return NULL;
        }
    }

    return packet;
}

/*  Reads a section of a DNS packet (Questions/RRs), given the number of items (individual
    questions/RRs) and a function to extract it                                             */
void *read_section(dns_packet_t *packet, uint16_t *byte_offset, int num_items, 
                    void *(*read_field)(dns_packet_t *, uint16_t *)){

    void **fields = NULL;

    if (num_items){
        fields = (void **)malloc(sizeof(void *)*num_items);
        assert(fields);

        for (int i = 0; i < num_items; i++){
            fields[i] = read_field(packet, byte_offset);
        }
    }

    return fields;
}

/*  Parses the given binary packet and returns a human-readable message struct  */
message_t *parse_packet(dns_packet_t *packet){

    message_t *msg = (message_t *)malloc(sizeof(message_t));
    assert(msg);

    msg->header = read_header(packet);
    uint16_t byte_offset = HEADER_LEN + 2; // +2 for the length bytes

    msg->questions = read_section(packet, &byte_offset, msg->header->qdcount, read_question);
    msg->answers = read_section(packet, &byte_offset, msg->header->ancount, read_RR);
    msg->authorities = read_section(packet, &byte_offset, msg->header->nscount, read_RR);
    msg->additional = read_section(packet, &byte_offset, msg->header->arcount, read_RR);
    
    return msg;
}

/*  Prints information about a DNS record - for testing purposes    */
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


/*  Creates a header with RCODE = 4, signifying unimplemented request   */
dns_header_t *create_error_header(int id){

    dns_header_t *header = (dns_header_t *)malloc(sizeof(dns_header_t));
    assert(header);

    header->id = id;
    header->qr = 1;
    header->opcode = 0;
    header->aa = 0;
    header->tc = 0;
    header->rd = 0;
    header->ra = 0;
    header->rcode = 4;
    header->qdcount = 0;
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;

    return header;
}

/*  Frees a packet  */
void free_packet(dns_packet_t *packet){

    free(packet->data);
    free(packet);
}

/*  Frees an array of pointers to questions   */
void free_question_array(question_t **array, int num_items){

    for (int i = 0; i < num_items; i++){
        free(array[i]);
    }
    free(array);
}

/*  Frees an array of pointers to RRs   */
void free_RR_array(RR_t **array, int num_items){

    for (int i = 0; i < num_items; i++){
        free(array[i]->rdata);
        free(array[i]);
    }
    free(array);
}

/*  Frees a message */
void free_message(message_t *msg){

    free_question_array(msg->questions, msg->header->qdcount);
    free_RR_array(msg->answers, msg->header->ancount);
    free_RR_array(msg->authorities, msg->header->nscount);
    free_RR_array(msg->additional, msg->header->arcount);
    free(msg->header);
    free(msg);
}

/*  Creates a binary DNS packet from the provided DNS message. Inverse of parse_packet()    
    Does not use message compression                                                        */                               
dns_packet_t *create_packet(message_t *msg){

    dns_packet_t *packet = (dns_packet_t *)malloc(sizeof(dns_packet_t));
    assert(packet);

    packet->len = 0;
    uint8_t *header = create_header_sequence(msg->header);
    packet->len += HEADER_LEN;

    uint8_t **questions = (uint8_t **)malloc(sizeof(uint8_t *)*(msg->header->qdcount));
    assert(questions);
    uint8_t **answers = (uint8_t **)malloc(sizeof(uint8_t *)*(msg->header->ancount));
    assert(answers);
    uint8_t **authorities = (uint8_t **)malloc(sizeof(uint8_t *)*(msg->header->nscount));
    assert(authorities);
    uint8_t **additional = (uint8_t **)malloc(sizeof(uint8_t *)*(msg->header->arcount));
    assert(additional);

   // Arrays to hold the sizes of each byte sequence
    int *questions_sizes = (int *)malloc(sizeof(int)*(msg->header->qdcount));
    assert(questions_sizes);
    int *answers_sizes = (int *)malloc(sizeof(int)*(msg->header->ancount));
    assert(answers_sizes);
    int *authorities_sizes = (int *)malloc(sizeof(int)*(msg->header->nscount));
    assert(authorities_sizes);
    int *additional_sizes = (int *)malloc(sizeof(int)*(msg->header->arcount));
    assert(additional_sizes);

    for (int i = 0; i < msg->header->qdcount; i++){
        questions[i] = create_question_sequence(msg->questions[i], &(questions_sizes[i]));
        packet->len += questions_sizes[i];
    }

    for (int i = 0; i < msg->header->ancount; i++){
        answers[i] = create_RR_sequence(msg->answers[i], &(answers_sizes[i]));
        packet->len += answers_sizes[i];
    }

    for (int i = 0; i < msg->header->nscount; i++){
        authorities[i] = create_RR_sequence(msg->authorities[i], &(authorities_sizes[i]));
        packet->len += authorities_sizes[i];
    }

    for (int i = 0; i < msg->header->arcount; i++){
        additional[i] = create_RR_sequence(msg->additional[i], &(additional_sizes[i]));
        packet->len += additional_sizes[i];
    }

    packet->data = (uint8_t *)malloc(sizeof(uint8_t)*(packet->len + 2)); // +2 to include length
    assert(packet->data);

    int offset = 0;

    uint16_t len = htons(packet->len);
    memcpy(&(packet->data[offset]), &len, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    memcpy(&(packet->data[offset]), header, HEADER_LEN);
    offset += HEADER_LEN;
    free(header);

    for (int i = 0; i < msg->header->qdcount; i++){
        memcpy(&(packet->data[offset]), questions[i], questions_sizes[i]);
        offset += questions_sizes[i];
        free(questions[i]);
    }

    for (int i = 0; i < msg->header->ancount; i++){
        memcpy(&(packet->data[offset]), answers[i], answers_sizes[i]);
        offset += answers_sizes[i];
        free(answers[i]);
    }

    for (int i = 0; i < msg->header->nscount; i++){
        memcpy(&(packet->data[offset]), authorities[i], authorities_sizes[i]);
        offset += authorities_sizes[i];
        free(authorities[i]);
    }

    for (int i = 0; i < msg->header->arcount; i++){
        memcpy(&(packet->data[offset]), additional[i], additional_sizes[i]);
        offset += additional_sizes[i];
        free(additional[i]);
    }

    free(questions);
    free(answers);
    free(authorities);
    free(additional);
    free(questions_sizes);
    free(answers_sizes);
    free(authorities_sizes);
    free(additional_sizes);
    
    return packet;
}


/*  Creates and a byte sequence representing the given header.  */
uint8_t *create_header_sequence(dns_header_t *header){

    uint8_t *sequence = (uint8_t *)calloc(HEADER_LEN, sizeof(uint8_t));
    assert(sequence);

    uint16_t id = htons(header->id);
    memcpy(&(sequence[0]), &id, 2); 

    // byte 4 bit 0
    sequence[2] = header->qr << 7;
    // byte 4 bits 1-4 (15 = 0b00001111)
    sequence[2] = sequence[2] | (header->opcode << 3);
    // byte 4 bit 5
    sequence[2] = sequence[2] | (header->aa << 2);
    // byte 4 bit 6
    sequence[2] = sequence[2] | (header->tc << 1);
    // byte 4 bit 7
    sequence[2] = sequence[2] | (header->rd);
    // byte 5 bit 0
    sequence[3] = header->ra << 7;
    // byte 5 bits 4-7 
    sequence[3] = sequence[3] | (header->rcode);

    uint16_t qdcount = htons(header->qdcount);
    memcpy(&(sequence[4]), &qdcount, 2);

    uint16_t ancount = htons(header->ancount);
    memcpy(&(sequence[6]), &ancount, 2);

    uint16_t nscount = htons(header->nscount);
    memcpy(&(sequence[8]), &nscount, 2);

    uint16_t arcount = htons(header->arcount);
    memcpy(&(sequence[10]), &arcount, 2);

    return sequence;
}

/*  Creates a byte sequence representing the given resource record. Sets total_size to size of 
    byte sequence   */
uint8_t *create_RR_sequence(RR_t *RR, int *total_size){

    uint8_t *sequence = create_name_sequence(RR->name, total_size);
    int offset = *total_size; // gets length of the name sequence only

    int size = offset + 3*sizeof(uint16_t) + sizeof(uint32_t) + RR->rdlength; // size of all fields

    sequence = (uint8_t *)realloc(sequence, size);
    assert(sequence);

    uint16_t type = htons(RR->type);
    memcpy(&(sequence[offset]), &type, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    uint16_t class = htons(RR->class);
    memcpy(&(sequence[offset]), &class, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    uint32_t ttl = htonl(RR->ttl);
    memcpy(&(sequence[offset]), &ttl, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    uint16_t rdlength = htons(RR->rdlength);
    memcpy(&(sequence[offset]), &rdlength, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    memcpy(&(sequence[offset]), RR->rdata, RR->rdlength);
    offset += RR->rdlength;

    (*total_size) = offset;
    return sequence;
}

/*  Creates a byte sequence representing the given question. Sets total_size to size of byte 
    sequence    */
uint8_t *create_question_sequence(question_t *question, int *total_size){

    uint8_t *sequence = create_name_sequence(question->qname, total_size);
    int offset = *total_size; // gets length of the name sequence only

    int size = offset + 2*sizeof(uint16_t); // size of all fields (type, class)

    sequence = (uint8_t *)realloc(sequence, size); 
    assert(sequence);

    uint16_t qtype = htons(question->qtype);
    memcpy(&(sequence[offset]), &qtype, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    uint16_t qclass = htons(question->qclass);
    memcpy(&(sequence[offset]), &qclass, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    (*total_size) = offset;
    return sequence;
}

/*  Creates a byte sequence representing the given string (domain name). Uses the label format, 
    where a length octet precedes each label. Sets total_size to size of byte sequence    */
uint8_t *create_name_sequence(char *name, int *total_size){

    // We have max size 2*(MAX_DNAME_CHARS) as theoretically, each char could have a preceding
    // octet
    uint8_t *sequence = (uint8_t *)calloc(2*MAX_DNAME_CHARS,sizeof(uint8_t)); 
    assert(sequence);

    int offset = 0;
    const char delim[2] = ".";
    char *token = strtok(name, delim);

    while (token){
        uint8_t len = strlen(token);
        memcpy(&(sequence[offset++]), &len, sizeof(uint8_t));
        memcpy(&(sequence[offset]), token, len);
        offset += len;

        token = strtok(NULL, delim); // get next token;
    }

    offset++; // to count final zero byte

    uint8_t *trimmed_sequence = (uint8_t *)malloc(sizeof(uint8_t)*offset);
    assert(trimmed_sequence);

    memcpy(trimmed_sequence, sequence, offset);
    free(sequence);

    (*total_size) = offset;
    return trimmed_sequence;
}
