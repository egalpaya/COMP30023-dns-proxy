/*************************************************************************************************/           
/*  COMP30023 Assignment 2                                                                       */
/*  Eishitha Galpayage Don                                                                       */
/*  993413                                                                                       */
/*  Functions to manage connections/sockets                                                      */
/*************************************************************************************************/
#ifndef CONNECTIONS_H
#define CONNECTIONS_H

#include "utils.h"
#include <poll.h>

/*  Creates a listener socket on the local IP and defined port. Sets it to listen.
    Returns the file descriptor */
int create_listener();

/*  Creates a socket and connection to the supplied upstream DNS server. Returns the file desc  */
int connect_upstream(char **argv);

/*  Accept incoming downstream connection on listener socket. Return the newly created socket   */
int connect_client(int listener_fd);

/*  Forwards a packet to the upstream server. Returns a socket/connection file descriptor for the
    connection to upstream server   */
int forward_packet(char **argv, dns_packet_t *packet);

/*  Send the final response downstream and close connection  */
void send_response(int conn_fd, dns_packet_t *packet);

/*  Adds a downstream connection/socket to pollfd array. For each downstream connection, we may 
    have an associated upstream connection fetching the response. Therefore we shall add two
    consecutive entries in the array, the first being downstream and second being upstream. 
    Initialise the second to -1, making poll() ignore at first, until later changed.  */
void add_fd(int fd, struct pollfd **fds, nfds_t *nfds, int *capacity);

/* Removes the two consecutive entries from pollfd array */
void delete_fd(int index, struct pollfd **fds, nfds_t *nfds);

void get_response2(int conn_fd);

#endif