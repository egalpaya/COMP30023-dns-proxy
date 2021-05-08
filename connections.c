/*************************************************************************************************/           
/*  COMP30023 Assignment 2                                                                       */
/*  Eishitha Galpayage Don                                                                       */
/*  993413                                                                                       */
/*  Functions to manage connections/sockets                                                      */
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

#define PORT "8053"
#define BACKLOG 20


/*  Creates a listener socket on the local IP and defined port. Sets it to listen.
    Returns the file descriptor */
int create_listener(){

    int status;
    struct addrinfo hints, *res;

    // Create hints structure - use iIPv4 and TCP
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM; 
    hints.ai_flags = AI_PASSIVE; 

    // Create listening address
    if ((status = getaddrinfo(NULL, PORT, &hints, &res)) != 0){
        fprintf(stderr, "getaddrinfo - listener: %s\n", gai_strerror(status));
        exit(EXIT_FAILURE);
    }

    // Create socket
    int listener_fd;
    if ((listener_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0){
        perror("socket - listener");
        exit(EXIT_FAILURE);
    }
    
    // Allow reuse of ports
    int enable = 1;
    if (setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Bind socket
    if (bind(listener_fd, res->ai_addr, res->ai_addrlen) < 0){
        perror("bind");
        exit(EXIT_FAILURE);
    }
    
    // Begin listening
    if (listen(listener_fd, BACKLOG) < 0){
        perror("listening");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);

    return listener_fd;
}

/*  Creates a socket and connection to the supplied upstream DNS server. Returns the file desc  */
int connect_upstream(char **argv){

    int status;
    struct addrinfo hints, *res;

    // Create hints structure - use iIPv4 and TCP
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM; 

    // Create upstream address
    if ((status = getaddrinfo(argv[1], argv[2], &hints, &res)) != 0){
        fprintf(stderr, "getaddrinfo - upstream: %s\n", gai_strerror(status));
        return -1;
    }

    // Create upstream socket
    int upstream_fd;
    if ((upstream_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0){
        perror("socket - upstream");
        return -1;
    }

    // Connect socket
    if (connect(upstream_fd, res->ai_addr, res->ai_addrlen) < 0){
        close(upstream_fd);
        perror("connect - upstream");
        return -1;
    }

    freeaddrinfo(res);

    return upstream_fd;
}

/*  Accept incoming downstream connection on listener socket. Return the newly created socket   */
int connect_client(int listener_fd){

    int conn_fd;
    struct sockaddr_storage client_addr;
    socklen_t len = sizeof(client_addr);

    if ((conn_fd = accept(listener_fd, (struct sockaddr *)&client_addr, &len)) < 0){
        close(conn_fd);
        perror("accept");
        return -1;
    }

    return conn_fd;
}

/*  Forwards a packet to the upstream server. Returns a socket/connection file descriptor for the
    connection to upstream server   */
int forward_packet(char **argv, dns_packet_t *packet){
    
    int upstream_fd, n;

    if ((upstream_fd = connect_upstream(argv)) < 0){
        close(upstream_fd);
        return -1;
    }
    
    // Send the packet in one go
    if ((n = send(upstream_fd, packet->data, packet->len + 2, 0)) != packet->len + 2){
        perror("send - upstream");
        return -1;
    }

    message_t *msg = parse_packet(packet);
    printf("message sent upstream:\n");
    //print_message(msg);
    return upstream_fd;
}

/*  Receive a query from downstream    */
dns_packet_t *get_query(int conn_fd){

    dns_packet_t *packet = read_packet(conn_fd);
    message_t *msg = parse_packet(packet);
    printf("message received from client:\n");
    //print_message(msg);
    return packet;
}

/*  Receives a response from the upstream server and closes the connection, returning the
    packet  */
dns_packet_t *get_response(int conn_fd){

    dns_packet_t *packet = read_packet(conn_fd);
    message_t *msg = parse_packet(packet);
    printf("message received from upstream:\n");
    //print_message(msg);
    close(conn_fd);
    return packet;
}

void get_response2(int conn_fd){

    uint8_t *buf = malloc(sizeof(uint8_t)*500);

    int i = 0;
    while(1){
        if ((read(conn_fd, &(buf[i++]), 1)) != 1){
            break;
        }
    }
    printf("%d bytes read\n", i);
    for (int j = 0; j < i; j++){
        if (j % 16 == 0){
            printf("\n");
        }
        printf("%x ", buf[j]);
    }
    printf("\n");
    free(buf);
}

/*  Send the final response downstream and close connection  */
void send_response(int conn_fd, dns_packet_t *packet){

    int n;

    // Send the packet in one go
    if ((n = send(conn_fd, packet->data, packet->len + 2, 0)) != packet->len + 2){
        perror("send - downstream");
        return;
    }

    message_t *msg = parse_packet(packet);
    printf("message sent back to client:\n");
    //print_message(msg);
    free_packet(packet);
    close(conn_fd);
}


/*  Adds a downstream connection/socket to pollfd array. For each downstream connection, we may 
    have an associated upstream connection fetching the response. Therefore we shall add two
    consecutive entries in the array, the first being downstream and second being upstream. 
    Initialise the second to -1, making poll() ignore at first, until later changed.  */
void add_fd(int fd, struct pollfd **fds, nfds_t *nfds, int *capacity){

    // If at capacity, quadruple size of array ( - 2 reflects adding two entries each time)
    if (*nfds > *capacity - 2){
        *capacity *= 4;

        *fds = (struct pollfd *)realloc(fds, *capacity);
        assert(fds);
    }

    // Add the downstream connection to the array
    (*fds)[*nfds].fd = fd;
    (*fds)[*nfds].events = POLLIN;
    (*nfds)++;

    // Add a placeholder for the potential upstream connection
    (*fds)[*nfds].fd = -1;
    (*fds)[*nfds].events = POLLIN;
    (*nfds)++;

}

/* Removes the two consecutive entries from pollfd array */
void delete_fd(int index, struct pollfd **fds, nfds_t *nfds){

    // Swap with last 2 entries
    (*fds)[index] = (*fds)[*nfds - 2];
    (*fds)[index+1] = (*fds)[*nfds -1];

    (*nfds) -= 2;
}