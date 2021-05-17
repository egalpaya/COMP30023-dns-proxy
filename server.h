/*************************************************************************************************/           
/*  COMP30023 Assignment 2                                                                       */
/*  Eishitha Galpayage Don                                                                       */
/*  993413                                                                                       */
/*  Functions to perform server operations/logic                                                 */
/*************************************************************************************************/
#ifndef SERVER_H
#define SERVER_H

#include <poll.h>

#include "utils.h"
#include "cache.h"

/*  Creates a DNS response packet with RCODE = 4, signifying unimplemented request, 
    in response to query with given ID  */
packet_t *create_error_packet(int id);

/*  Examines the first question of given query. Returns 0 if it is a valid AAAA question, 
    -1 if there is a question but it's not AAAA, -2 if there are no questions.  */
int check_query(message_t *query);

/*  Logs a valid query. Should only be called after check_query() returns 0 or -1   */
void log_query(message_t *query);

/*  Examines the first answer of given response and returns 0 if it is AAAA, -1 otherwise (or if
    no answer exists)  */
int check_response(message_t *response);

/*  Logs a valid response. Should only be called after check_response() returns 0*/
void log_response(message_t *response);

/*  Accepts an incoming connection from a client and adds to pool of FDs    */
void accept_client_connection(int listener_fd, struct pollfd **fds, nfds_t *nfds, int *capacity);

/*  Reads in a query from the client and processes it, sending back a response or forwarding 
    upstream.   */
void process_client_query(struct pollfd *fds, nfds_t *nfds, cache_t *cache, char **argv, int i);

/*  Reads in a response from upstream server and processes it, sending it back to client and
    adding to cache if valid.   */
void process_upstream_response(struct pollfd *fds, nfds_t *nfds, cache_t *cache, int i);

/*  Main server loop, using poll() for non-blocking operation - basic structure of poll() loop
    adapted from https://beej.us/guide/bgnet/html/#poll */
void run_server(char **argv);

#endif