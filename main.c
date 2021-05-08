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


void run_server(char **argv){

    // Create pollfd structs for non-blocking operation
    nfds_t nfds = 0;
    int capacity = INITIAL_SOCKET_CAP;
    struct pollfd *fds = (struct pollfd *)malloc(sizeof(struct pollfd)*capacity);
    assert(fds);

    int listener_fd = create_listener();
    add_fd(listener_fd, &fds, &nfds, &capacity);

    cache_t *cache = create_cache();
    
    while (1){

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
                    break;
                } else if (i % 2 == 0) {
                    // Even index means this is a downstream client

                    dns_packet_t *packet = read_packet(fds[i].fd);
                    message_t *msg = parse_packet(packet);
                    process_message(msg);

                    dns_packet_t *cache_entry = get_cache_entry(cache, msg);

                    if (cache_entry){
                        // response exists in cache, so send it back and close connections
                        send_response(fds[i].fd, cache_entry);
                        delete_fd(i, &fds, &nfds);
                        continue;
                    }

                    int upstream_fd = forward_packet(argv, packet);
                    fds[i+1].fd = upstream_fd;

                    break;
                } else {
                    // This must be a response from the upstream connection
                    dns_packet_t *response = read_packet(fds[i].fd);
                    close(fds[i].fd);
                    // Send it back to client
                    send_response(fds[i-1].fd, response);
                    
                    // Remove the now closed connections from array
                    delete_fd(i-1, &fds, &nfds);
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