/*************************************************************************************************/           
/*  COMP30023 Assignment 2                                                                       */
/*  Eishitha Galpayage Don                                                                       */
/*  993413                                                                                       */
/*  Functions to perform server operations/logic                                                 */
/*************************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "connections.h"
#include "parser.h"
#include "server.h"

#define INITIAL_SOCKET_CAP 8
#define MAX_TIMEOUT_LEN 10000

/*  Creates a DNS response packet with RCODE = 4, signifying unimplemented request, 
    in response to query with given ID  */
packet_t *create_error_packet(int id){

    header_t *header = (header_t *)malloc(sizeof(header_t));
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

    message_t *response = (message_t *)malloc(sizeof(message_t));
    assert(response);

    response->header = header;
    response->questions = NULL;
    response->answers = NULL;
    response->authorities = NULL;
    response->additional = NULL;

    packet_t *packet = create_packet(response);
    free_message(response);

    return packet;
}

/*  Examines the first question of given query. Returns 0 if it is a valid AAAA question, 
    -1 if there is a question but it's not AAAA, -2 if there are no questions.  */
int check_query(message_t *query){

    if (query->header->qdcount > 0){
        if (query->questions[0]->qtype == 28){
            return 0;
        }
        return -1;
    }
    return -2;
}

/*  Logs a valid query. Should only be called after check_query() returns 0 or -1   */
void log_query(message_t *query){

    char buffer[MAX_LOG_ENTRY];
    char name[MAX_DNAME_CHARS];

    strcpy(name, query->questions[0]->qname);
    remove_trailing_dot(name);
    snprintf(buffer, MAX_LOG_ENTRY, "requested %s\n", name);
    write_log(buffer);
}

/*  Examines the first answer of given response and returns 0 if it is AAAA, -1 otherwise (or if
    no answer exists)  */
int check_response(message_t *response){

    if (response->header->ancount > 0 && response->answers[0]->type == 28){
        return 0;
    } else {
        return -1;
    }
}

/*  Logs a valid response. Should only be called after check_response() returns 0*/
void log_response(message_t *response){

    char buffer[MAX_LOG_ENTRY];
    char ip[INET6_ADDRSTRLEN];
    char name[MAX_DNAME_CHARS];

    strcpy(name, response->questions[0]->qname);
    remove_trailing_dot(name);
    inet_ntop(AF_INET6, response->answers[0]->rdata, ip, INET6_ADDRSTRLEN);
    snprintf(buffer, MAX_LOG_ENTRY, "%s is at %s\n", name, ip);
    write_log(buffer);
}

/*  Accepts an incoming connection from a client and adds to pool of FDs    */
void accept_client_connection(int listener_fd, struct pollfd **fds, nfds_t *nfds, int *capacity){

    int client_fd = connect_client(listener_fd);
    add_fd(client_fd, fds, nfds, capacity);
}

/*  Reads in a query from the client and processes it, sending back a response or forwarding 
    upstream.   */
void process_client_query(struct pollfd *fds, nfds_t *nfds, cache_t *cache, char **argv, int i){

    packet_t *packet = read_packet(fds[i].fd);
    message_t *query = parse_packet(packet);
    packet_t *response_packet = NULL;

    int valid = check_query(query);

    if (valid > -2){
        // log query if it contains a question
        log_query(query);
    }

    if (valid == -1){
        // if request is unimplemented, create a packet with rcode 4
        write_log("unimplemented request\n");
        response_packet = create_error_packet(query->header->id);
    } else if ((response_packet = get_cache_entry(cache, query))){ 
        // if we were able to fetch response from cache, log it
        message_t *response = parse_packet(response_packet);
        log_response(response);
        free_message(response);
    } else {   
        // send upstream, updating the socket file descriptor
        int upstream_fd = forward_packet(argv, packet);
        fds[i+1].fd = upstream_fd;
    }

    // if we have a response (either error or cache), send it
    if (response_packet){
        send_response(fds[i].fd, response_packet);
        close(fds[i].fd);
        delete_fd(i, &fds, nfds);
        free_packet(response_packet);
    }

    free_packet(packet);
    free_message(query);
}

/*  Reads in a response from upstream server and processes it, sending it back to client and
    adding to cache if valid.   */
void process_upstream_response(struct pollfd *fds, nfds_t *nfds, cache_t *cache, int i){

    packet_t *response_packet = read_packet(fds[i].fd);
    message_t *response = parse_packet(response_packet);
    close(fds[i].fd);

    // if the response has a valid AAAA answer, add it to cache and log it
    int valid_answer = check_response(response);
    if (valid_answer == 0){
        add_cache_entry(cache, response);
        log_response(response);
    }

    // send the response back to client, regardless of whether a valid answer exists
    send_response(fds[i-1].fd, response_packet);
    close(fds[i-1].fd);
    delete_fd(i-1, &fds, nfds);

    if (valid_answer == -1){
        // response had no valid answer and therefore was not cached, so free it
        free_message(response);
    }

    free_packet(response_packet);   
}

/*  Main server loop, using poll() for non-blocking operation - basic structure of poll() loop
    adapted from https://beej.us/guide/bgnet/html/#poll */
void run_server(char **argv){

    // create pollfd structs for non-blocking operation
    nfds_t nfds = 0;
    int capacity = INITIAL_SOCKET_CAP;
    struct pollfd *fds = (struct pollfd *)malloc(sizeof(struct pollfd)*capacity);
    assert(fds);

    // create listener and add to set of file descriptors
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
                    // odd index, therefore a response from the upstream connection
                    process_upstream_response(fds, &nfds, cache, i);
                    break;
                }
            }
        }
    }

    free_cache(cache);
    close(listener_fd);
    delete_fd(0, &fds, &nfds); // delete listener (index 0)
    free(fds);
}
