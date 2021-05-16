/*************************************************************************************************/           
/*  COMP30023 Assignment 2                                                                       */
/*  Eishitha Galpayage Don                                                                       */
/*  993413                                                                                       */
/*  Main function                                                                                */
/*************************************************************************************************/
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include "utils.h"
#include "parser.h"
#include "connections.h"
#include "cache.h"

#define CACHE
#define NONBLOCKING
#define INITIAL_SOCKET_CAP 8
#define MAX_TIMEOUT_LEN 10000

/*  Creates a DNS response packet with RCODE = 4, signifying unimplemented request, 
    in response to query with given ID  */
dns_packet_t *create_error_packet(int id){

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

    message_t *msg = (message_t *)malloc(sizeof(message_t));
    assert(msg);

    msg->header = header;
    msg->questions = NULL;
    msg->answers = NULL;
    msg->authorities = NULL;
    msg->additional = NULL;

    dns_packet_t *packet = create_packet(msg);
    free_message(msg);

    return packet;
}

/*  Examines given query and returns 0 if it is AAAA, -1 otherwise, writing request to
    log as well  */
int check_query(message_t *query){

    char buffer[MAX_LOG_ENTRY];
    char name[MAX_DNAME_CHARS];

    if (query->header->qdcount){
        strcpy(name, query->questions[0]->qname);
        remove_trailing_dot(name);
        snprintf(buffer, MAX_LOG_ENTRY, "requested %s\n", name);
        write_log(buffer);
    }

    if (query->questions[0]->qtype != 28){
        snprintf(buffer, MAX_LOG_ENTRY, "unimplemented request\n");
        write_log(buffer);
        return -1;
    }

    return 0;
}

void process_response(message_t *msg){

    char buffer[MAX_LOG_ENTRY];
    char ip[INET6_ADDRSTRLEN];
    char name[MAX_DNAME_CHARS];

    if (msg->header->ancount && msg->answers[0]->type == 28){
        strcpy(name, msg->questions[0]->qname);
        remove_trailing_dot(name);
        inet_ntop(AF_INET6, msg->answers[0]->rdata, ip, INET6_ADDRSTRLEN);
        snprintf(buffer, MAX_LOG_ENTRY, "%s is at %s\n", name, ip);
        write_log(buffer);
    }
}

/*  Accepts an incoming connection from a client and adds to pool of sockets to monitor */
void accept_client_connection(int listener_fd, struct pollfd **fds, nfds_t *nfds, int *capacity){

    int client_fd = connect_client(listener_fd);
    add_fd(client_fd, fds, nfds, capacity);
}

/*  Reads in a query from the client and processes it   */
void process_client_query(struct pollfd *fds, nfds_t *nfds, cache_t *cache, char **argv, int i){

    dns_packet_t *packet = read_packet(fds[i].fd);
    message_t *msg = parse_packet(packet);

    // If request is unimplemented, send back a packet with rcode 4
    if ((check_query(msg)) == -1){
        dns_packet_t *response_packet = create_error_packet(msg->header->id);
        send_response(fds[i].fd, response_packet);
        delete_fd(i, &fds, nfds);
        free_packet(response_packet);
        return;
    }
    
    // request is valid, so check the cache
    dns_packet_t *cache_entry = get_cache_entry(cache, msg);
    if (cache_entry){
        // response exists in cache, so send it back and close connections
        message_t *response = parse_packet(cache_entry);
        process_response(response);
        send_response(fds[i].fd, cache_entry);
        delete_fd(i, &fds, nfds);
        free_message(response);
        return;
    }

    // cache is empty, so forward upstream
    int upstream_fd = forward_packet(argv, packet);
    fds[i+1].fd = upstream_fd;

    free_packet(packet);
    free_message(msg);
}

/*  Reads in a response from upstream server and processes it   */
void process_upstream_response(struct pollfd *fds, nfds_t *nfds, cache_t *cache, int i){

    dns_packet_t *response_packet = read_packet(fds[i].fd);
    close(fds[i].fd);

    // process it and add it to cache if an answer is found
    message_t *response = parse_packet(response_packet);
    process_response(response);

    if (response->header->ancount){
        add_cache_entry(cache, response, response_packet);
    }
    // send back to client
    send_response(fds[i-1].fd, response_packet);

    // remove the now closed connections from array
    delete_fd(i-1, &fds, nfds);

    if (!(response->header->ancount)){
        // response had no answer and was not cached, so free it
        free_packet(response_packet);
        free_message(response);
    }   
}

/*  Main server loop, using poll() for non-blocking operation  */
void run_server(char **argv){

    // create pollfd structs for non-blocking operation
    nfds_t nfds = 0;
    int capacity = INITIAL_SOCKET_CAP;
    struct pollfd *fds = (struct pollfd *)malloc(sizeof(struct pollfd)*capacity);
    assert(fds);

    int listener_fd = create_listener();
    add_fd(listener_fd, &fds, &nfds, &capacity);

    cache_t *cache = create_cache();
    
    while (1){

        if (poll(fds, nfds, MAX_TIMEOUT_LEN) < 0){
            perror("poll");
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i < nfds; i++){

            if (fds[i].revents & POLLIN){
            
                if (fds[i].fd == listener_fd){
                    accept_client_connection(listener_fd, &fds, &nfds, &capacity);
                    break;
                } else if (i % 2 == 0) {
                    // even index means this is a downstream client
                    process_client_query(fds, &nfds, cache, argv, i);
                    break;
                } else {
                    // this must be a response from the upstream connection
                    process_upstream_response(fds, &nfds, cache, i);
                    break;
                }
            }
        }
    }

    // Remove listener from array and close it
    delete_fd(0, &fds, &nfds);
    close(listener_fd);
    free(fds);
}

int main(int argc, char **argv){

    if (argc != 3){
        printf("usage: dns_svr [upstream_server_ip] [port]\n");
        exit(EXIT_FAILURE);
    }

    run_server(argv);

}


/* TO DO: check why TASK 3 ve1 failing log entry. Decrement TTL for cache (using create_packet()). 
    Fix log entries for cache eviction. Tidy up and refactor code (get parser.c < 500 lines). */