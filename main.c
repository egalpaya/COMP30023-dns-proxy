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

#define PORT "8053"
#define BACKLOG 20
#define MAX_LOG_ENTRY 512
#define INITIAL_SOCKET_CAP 8

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
    if ((n = send(upstream_fd, packet->data, packet->len, 0)) != packet->len){
        perror("send - upstream");
        return -1;
    }

    return upstream_fd;
}

/*  Receive a query from downstream    */
void get_query(int conn_fd){


}

/*  Receives a response from the upstream server and closes the connection, returning the
    packet  */
dns_packet_t *get_response(int conn_fd){

    dns_packet_t *packet = read_packet(conn_fd);
    close(conn_fd);
    return packet;
}

/*  Send the final response downstream and close connection  */
void send_response(int conn_fd, dns_packet_t *packet){

    int n;

    // Send the packet in one go
    if ((n = send(conn_fd, packet->data, packet->len, 0)) != packet->len){
        perror("send - downstream");
        return;
    }

    free_packet(packet);
    close(conn_fd);
}

// /*  Creates a pollfd struct containing the given file descriptor    */
// struct pollfd *create_pollfd(int fd){

//     struct pollfd *p = (struct pollfd *)malloc(sizeof(struct pollfd));
//     assert(p);
    
//     p->fd = fd;
//     p->events = POLLIN;

//     return p;
// }

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

    // struct pollfd *entry1 = *fds[index];
    // struct pollfd *entry2 = *fds[index+1];

    // Swap with last 2 entries
    (*fds)[index] = (*fds)[*nfds - 2];
    (*fds)[index+1] = (*fds)[*nfds -1];
    // *fds[*nfds - 2] = NULL;
    // *fds[*nfds - 1] = NULL;

    nfds -= 2;

    // free(entry1);
    // free(entry2);
}


void run_server(char **argv){

    // Create pollfd structs for non-blocking operation
    nfds_t nfds = 0;
    int capacity = INITIAL_SOCKET_CAP;
    struct pollfd *fds = (struct pollfd *)malloc(sizeof(struct pollfd)*capacity);
    assert(fds);

    int listener_fd = create_listener();
    add_fd(listener_fd, &fds, &nfds, &capacity);
    
    int iter = 0;
    while (iter++ < 10){
        printf("iter: %d\n", iter);
        if (poll(fds, nfds, 1000) < 0){
            perror("poll");
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i < nfds; i++){

            if (fds[i].revents & POLLIN){

                if (fds[i].fd == listener_fd){
                    // Listener has a downstream client ready to connect, so accept and add to array
                    int client_fd = connect_client(listener_fd);
                    add_fd(client_fd, &fds, &nfds, &capacity);
                } else if (i % 2 == 0) {
                    // Even index means this is a downstream client

                    // process the received packet
                } else {
                    // This is a response from the upstream connection
                    dns_packet_t *response = get_response(fds[i].fd);
                    
                    // Send it back to client
                    send_response(fds[i-1].fd, response);
                    
                    // Remove the now closed connections from array
                    delete_fd(i-1, &fds, &nfds);
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