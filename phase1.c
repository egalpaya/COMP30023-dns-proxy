/*************************************************************************************************/           
/*  COMP30023 Assignment 2                                                                       */
/*  Eishitha Galpayage Don                                                                       */
/*  993413                                                                                       */
/*  Phase 1                                                                                      */
/*************************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include "utils.h"
#include "parser.h"

#define MAX_LOG_ENTRY 512

void remove_trailing_dot(char *str){

    char *last_dot = strrchr(str, '.');
    *last_dot = '\0';
}

void process_message(message_t *msg){

    char buffer[MAX_LOG_ENTRY];
    char ip[INET6_ADDRSTRLEN];
    char name[MAX_DNAME_CHARS];

    if (msg->header->qr == 0){
        if (msg->header->qdcount && msg->questions[0]->qtype == 28){
            strcpy(name, msg->questions[0]->qname);
            remove_trailing_dot(name);
            snprintf(buffer, MAX_LOG_ENTRY, "requested %s\n", name);
        } else {
            snprintf(buffer, MAX_LOG_ENTRY, "unimplemented request\n");
        }
    } else {
        if (msg->header->ancount && msg->answers[0]->type == 28){
            strcpy(name, msg->answers[0]->name);
            remove_trailing_dot(name);
            inet_ntop(AF_INET6, msg->answers[0]->rdata, ip, INET6_ADDRSTRLEN);
            snprintf(buffer, MAX_LOG_ENTRY, "%s is at %s\n", name, ip);
        }
    }

    write_log(buffer);
}

int main(int argc, char **argv){
    
    dns_packet_t *packet = read_packet(STDIN_FILENO);
    message_t *msg = parse_packet(packet);

    process_message(msg);

    return 0;
}
                                                                           