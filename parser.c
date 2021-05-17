/*************************************************************************************************/           
/*  COMP30023 Assignment 2                                                                       */
/*  Eishitha Galpayage Don                                                                       */
/*  993413                                                                                       */
/*  Functions to parse and create DNS packets                                                    */
/*************************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "parser.h"

#define HEADER_LEN 12   // includes 2 byte message length

/*  Reads a DNS packet from the given fd and returns it as a struct    */
packet_t *read_packet(int fd){

    // read the two byte header
    uint16_t len_n;
    if ((read(fd, &len_n, 2) != 2)){
        fprintf(stderr, "error reading length of packet\n");
        return NULL;
    }
    uint16_t len_h = ntohs(len_n);
    
    // create struct and allocate memory
    packet_t *packet = (packet_t *)malloc(sizeof(packet_t));
    assert(packet);
    packet->len = len_h;
    packet->data = (uint8_t *)malloc(sizeof(uint8_t)*(len_h+2)); // include 2 bytes for length
    assert(packet->data); 

    // copy the length bytes
    memcpy(&(packet->data[0]), &len_n, 2);

    // read in payload bytes from stream
    for (int i = 0; i < len_h; i++){
        if ((read(fd, &packet->data[i+2], 1)) != 1){ // indexing offset by 2 for length bytes
            fprintf(stderr, "error reading packet\n");
            return NULL;
        }
    }

    return packet;
}

/*  Parses the given binary packet and returns a human-readable message struct  */
message_t *parse_packet(packet_t *packet){

    message_t *msg = (message_t *)malloc(sizeof(message_t));
    assert(msg);

    uint16_t offset = 0; // track our position in the packet
    msg->header = read_header(packet);
    offset += HEADER_LEN + 2; // +2 for the length bytes

    msg->questions = read_section(packet, &offset, msg->header->qdcount, read_question);
    msg->answers = read_section(packet, &offset, msg->header->ancount, read_RR);
    msg->authorities = read_section(packet, &offset, msg->header->nscount, read_RR);
    msg->additional = read_section(packet, &offset, msg->header->arcount, read_RR);
    
    return msg;
}

/*  Reads a section of a DNS packet (Questions/RRs), given the number of items (individual
    questions/RRs) and a function to extract it. Returns an array of pointers to each item  */
void *read_section(packet_t *packet, uint16_t *offset, int num_items, 
                    void *(*read_field)(packet_t *, uint16_t *)){

    void **fields = NULL;

    if (num_items){
        fields = (void **)malloc(sizeof(void *)*num_items);
        assert(fields);

        for (int i = 0; i < num_items; i++){
            fields[i] = read_field(packet, offset);
        }
    }

    return fields;
}

/*  Reads the header of the given packet, returning it as a struct  */
header_t *read_header(packet_t *packet){
    
    header_t *header = (header_t *)malloc(sizeof(header_t));
    assert(header);

    uint16_t offset = 2; // data starts at byte 2 
    cpy_int_ntoh(packet, &offset, 2, &(header->id));
    
    // byte 2 bit 0
    header->qr = packet->data[offset] >> 7;
    // byte 2 bits 1-4 (15 = 0b00001111)
    header->opcode = (packet->data[offset] >> 3) & 15;
    // byte 2 bit 5
    header->aa = (packet->data[offset] >> 2) & 1;
    // byte 2 bit 6
    header->tc = (packet->data[offset] >> 1) & 1;
    // byte 2 bit 7
    header->rd = packet->data[offset++] & 1;
    // byte 3 bit 0
    header->ra = packet->data[offset] >> 7;
    // byte 3 bits 4-7 (15 = 0b00001111)
    header->rcode = packet->data[offset++] & 15;
    
    cpy_int_ntoh(packet, &offset, 2, &(header->qdcount));
    cpy_int_ntoh(packet, &offset, 2, &(header->ancount));
    cpy_int_ntoh(packet, &offset, 2, &(header->nscount));
    cpy_int_ntoh(packet, &offset, 2, &(header->arcount));

    return header;
}

/*  Reads a question section of the given packet at the given offset, returning it as a struct  */
void *read_question(packet_t *packet, uint16_t *offset){

    question_t *question = (question_t *)malloc(sizeof(question_t));
    assert(question);

    memset(question->qname, 0, MAX_DNAME_CHARS);

    read_domain_name(packet, offset, question->qname);

    cpy_int_ntoh(packet, offset, 2, &(question->qtype));
    cpy_int_ntoh(packet, offset, 2, &(question->qclass));

    return question;
}

/*  Reads a resource record of the given packet at the given offset, returning it as a struct   */
void *read_RR(packet_t *packet, uint16_t *offset){

    RR_t *rr = (RR_t *)malloc(sizeof(RR_t));
    assert(rr);

    memset(rr->name, 0, MAX_DNAME_CHARS);

    // Check if message compression is used (2 leading bits of byte are both 1)
    // Note: 3 = 0b00000011
    if (packet->data[*offset] >> 6 == 3){

        uint16_t pointer; 
        cpy_int_ntoh(packet, offset, 2, &pointer);

        pointer = pointer & 16383;  // remove 2 leading bits (NOTE 16383 = 0b0011111111111111)
        pointer += 2;   // account for 2 length bytes at start of packet

        read_domain_name(packet, &pointer, rr->name);
    } else {
        read_domain_name(packet, offset, rr->name);
    }

    // read in integer fields
    cpy_int_ntoh(packet, offset, 2, &(rr->type));
    cpy_int_ntoh(packet, offset, 2, &(rr->class));
    cpy_int_ntoh(packet, offset, 4, &(rr->ttl));
    cpy_int_ntoh(packet, offset, 2, &(rr->rdlength));

    // allocate memory and read rdata
    rr->rdata = (uint8_t *)malloc(sizeof(uint8_t)*(rr->rdlength));
    assert(rr->rdata);

    memcpy(rr->rdata, &(packet->data[*offset]), rr->rdlength);
    (*offset) += rr->rdlength;

    return rr;
}

/*  Reads a domain name encoded with labels (RFC1035 4.1.2.) into dest string   */
void read_domain_name(packet_t *packet, uint16_t *offset, char *dest){

    // sequentially write each label to dest string
    while (packet->data[*offset] != 0){
        uint8_t len = packet->data[(*offset)++];
        strncat(dest, (char *)&(packet->data[*offset]), len);
        strcat(dest, ".");
        (*offset) += len;
    }
    (*offset)++;
}

/*  Copies n bytes (as ints) from the network order packet to host order message field (dest), 
    incrementing the offset by n.  */
void cpy_int_ntoh(packet_t *packet, uint16_t *offset, int n, void *dest){

    memcpy(dest, &(packet->data[*offset]), n);

    if (n == 4){
        *(uint32_t *)dest = ntohl(*(uint32_t *)dest);
    } else if (n == 2){
        *(uint16_t *)dest = ntohs(*(uint16_t *)dest);
    }

    *(offset) += n;
}

/*  Creates a binary DNS packet from the provided DNS message. Inverse of parse_packet().    
    Does not use message compression    */                               
packet_t *create_packet(message_t *msg){

    packet_t *packet = (packet_t *)malloc(sizeof(packet_t));
    assert(packet);

    // create header bytes
    packet->len = 0;
    uint8_t *header = create_header_sequence(msg->header);
    packet->len += HEADER_LEN;

    // allocate memory for each section
    uint8_t **questions = (uint8_t **)malloc(sizeof(uint8_t *)*(msg->header->qdcount));
    assert(questions);
    uint8_t **answers = (uint8_t **)malloc(sizeof(uint8_t *)*(msg->header->ancount));
    assert(answers);
    uint8_t **authorities = (uint8_t **)malloc(sizeof(uint8_t *)*(msg->header->nscount));
    assert(authorities);
    uint8_t **additional = (uint8_t **)malloc(sizeof(uint8_t *)*(msg->header->arcount));
    assert(additional);

    // create arrays to hold the sizes of each byte sequence in each section
    int *questions_sizes = (int *)malloc(sizeof(int)*(msg->header->qdcount));
    assert(questions_sizes);
    int *answers_sizes = (int *)malloc(sizeof(int)*(msg->header->ancount));
    assert(answers_sizes);
    int *authorities_sizes = (int *)malloc(sizeof(int)*(msg->header->nscount));
    assert(authorities_sizes);
    int *additional_sizes = (int *)malloc(sizeof(int)*(msg->header->arcount));
    assert(additional_sizes);

    // populate the byte sequences for each section
    create_section_sequence(questions, questions_sizes, msg->header->qdcount, 
                        (void **)(msg->questions), &(packet->len), create_question_sequence);
    create_section_sequence(answers, answers_sizes, msg->header->ancount,
                        (void **)(msg->answers), &(packet->len), create_RR_sequence);
    create_section_sequence(authorities, authorities_sizes, msg->header->nscount,
                        (void **)(msg->authorities), &(packet->len), create_RR_sequence);
    create_section_sequence(additional, additional_sizes, msg->header->arcount,
                        (void **)(msg->additional), &(packet->len), create_RR_sequence);
    
    // create the packet
    packet->data = (uint8_t *)malloc(sizeof(uint8_t)*(packet->len + 2)); // +2 to include length
    assert(packet->data);

    // populate packet by concatenating bytes
    uint16_t offset = 0;
    cpy_int_hton(&(packet->len), &offset, 2, packet->data); // length bytes

    memcpy(&(packet->data[offset]), header, HEADER_LEN);
    offset += HEADER_LEN;

    concat_section(questions, questions_sizes, msg->header->qdcount, &offset, packet->data);
    concat_section(answers, answers_sizes, msg->header->ancount, &offset, packet->data);
    concat_section(authorities, authorities_sizes, msg->header->nscount, &offset, packet->data);
    concat_section(additional, additional_sizes, msg->header->arcount, &offset, packet->data);

    free_array((void **)questions, msg->header->qdcount);
    free_array((void **)answers, msg->header->ancount);
    free_array((void **)authorities, msg->header->nscount);
    free_array((void **)additional, msg->header->arcount);
    free(questions_sizes);
    free(answers_sizes);
    free(authorities_sizes);
    free(additional_sizes);
    free(header);

    return packet;
}

/*  Concatenates the bytes in the given array, writing to the dest array at the offset    */
void concat_section(uint8_t **array, int *sizes, int num_items, uint16_t *offset, uint8_t *dest){

    for (int i = 0; i < num_items; i++){
        memcpy(&(dest[*offset]), array[i], sizes[i]);
        (*offset) += sizes[i];
    }
}

/*  Populates an array of byte sequences, with each entry representing a section (question/RR) 
    of the DNS message. The sizes array will be populated with the number of bytes in each entry. 
    A function is passed in, either create_question_sequence() or create_RR_sequence(), which 
    does the work of converting the human readable section to bytes. Also updates len to reflect
    size of sequence.   */
void create_section_sequence(uint8_t **array, int *sizes, int num_entries, void **section,
                            uint16_t *len, uint8_t *(*create_field_sequence)(void *, int *)){

    for (int i = 0; i < num_entries; i++){
        array[i] = create_field_sequence(section[i], &(sizes[i]));
        *len += sizes[i];
    }
}

/*  Creates a byte sequence representing the given header.  */
uint8_t *create_header_sequence(header_t *header){

    uint8_t *sequence = (uint8_t *)calloc(HEADER_LEN, sizeof(uint8_t));
    assert(sequence);

    uint16_t offset = 0; 
    cpy_int_hton(&(header->id), &offset, 2, sequence);

    // byte 2 bit 0
    sequence[offset] = header->qr << 7;
    // byte 2 bits 1-4 (15 = 0b00001111)
    sequence[offset] = sequence[offset] | (header->opcode << 3);
    // byte 2 bit 5
    sequence[offset] = sequence[offset] | (header->aa << 2);
    // byte 2 bit 6
    sequence[offset] = sequence[offset] | (header->tc << 1);
    // byte 2 bit 7
    sequence[offset] = sequence[offset] | (header->rd);
    offset++;
    // byte 3 bit 0
    sequence[offset] = header->ra << 7;
    // byte 3 bits 4-7 
    sequence[offset] = sequence[offset] | (header->rcode);
    offset++;

    cpy_int_hton(&(header->qdcount), &offset, 2, sequence);
    cpy_int_hton(&(header->ancount), &offset, 2, sequence);
    cpy_int_hton(&(header->nscount), &offset, 2, sequence);
    cpy_int_hton(&(header->arcount), &offset, 2, sequence);

    return sequence;
}

/*  Creates a byte sequence representing the given resource record. Sets total_size to size of 
    byte sequence   */
uint8_t *create_RR_sequence(void *RR_ptr, int *total_size){

    RR_t *RR = (RR_t *)RR_ptr;
    uint8_t *sequence = create_name_sequence(RR->name, total_size);
    uint16_t offset = *total_size; // gets length of the name sequence only

    int size = offset + 3*sizeof(uint16_t) + sizeof(uint32_t) + RR->rdlength; // size of all fields

    sequence = (uint8_t *)realloc(sequence, size);
    assert(sequence);

    cpy_int_hton(&(RR->type), &offset, 2, sequence);
    cpy_int_hton(&(RR->class), &offset, 2, sequence);
    cpy_int_hton(&(RR->ttl), &offset, 4, sequence);
    cpy_int_hton(&(RR->rdlength), &offset, 2, sequence);

    memcpy(&(sequence[offset]), RR->rdata, RR->rdlength);
    offset += RR->rdlength;

    (*total_size) = offset;
    return sequence;
}

/*  Creates a byte sequence representing the given question. Sets total_size to size of byte 
    sequence    */
uint8_t *create_question_sequence(void *question_ptr, int *total_size){

    question_t *question = (question_t *)question_ptr;
    uint8_t *sequence = create_name_sequence(question->qname, total_size);
    uint16_t offset = *total_size; // gets length of the name sequence only

    int size = offset + 2*sizeof(uint16_t); // size of all fields (type, class)

    sequence = (uint8_t *)realloc(sequence, size); 
    assert(sequence);

    cpy_int_hton(&(question->qtype), &offset, 2, sequence);
    cpy_int_hton(&(question->qclass), &offset, 2, sequence);

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

    // make a copy, as strtok modifies the string
    char name_cpy[MAX_DNAME_CHARS];
    strcpy(name_cpy, name);

    uint16_t offset = 0;
    const char delim[2] = ".";
    char *token = strtok(name_cpy, delim);

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

/*  Copies n bytes (as ints) from the host order src to network order dest, 
    incrementing the offset by n.  */
void cpy_int_hton(void *src, uint16_t *offset, int n, uint8_t *dest){

    if (n == 4){
        uint32_t value = htonl(*(uint32_t *)src);
        memcpy(&(dest[*offset]), &value, n);
    } else if (n == 2){
        uint16_t value = htons(*(uint16_t *)src);
        memcpy(&(dest[*offset]), &value, n);
    }

    *(offset) += n;
}

/*  Frees a packet  */
void free_packet(packet_t *packet){

    free(packet->data);
    free(packet);
}

/*  Frees an array of pointers  */
void free_array(void **array, int num_items){

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

    free_array((void **)msg->questions, msg->header->qdcount);
    free_RR_array(msg->answers, msg->header->ancount);
    free_RR_array(msg->authorities, msg->header->nscount);
    free_RR_array(msg->additional, msg->header->arcount);
    free(msg->header);
    free(msg);
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
