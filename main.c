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

/*  Examines given query and returns 0 if it is AAAA, -1 otherwise, writing to log as well  */
int process_query(message_t *query){

    char buffer[MAX_LOG_ENTRY];
    char name[MAX_DNAME_CHARS];
    int success;

    if (query->header->qdcount && query->questions[0]->qtype == 28){
        strcpy(name, query->questions[0]->qname);
        remove_trailing_dot(name);
        snprintf(buffer, MAX_LOG_ENTRY, "requested %s\n", name);
        success = 0;
    } else {
        snprintf(buffer, MAX_LOG_ENTRY, "unimplemented request\n");
        success = -1;
    }

    write_log(buffer);
    return success;
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

                    // If request is unimplemented, send back a packet with rcode 4
                    if ((process_query(msg)) == -1){
                        dns_header_t *response_header = create_error_header(msg->header->id);
                        dns_packet_t *response_packet = create_header_packet(response_header);
                        send_response(fds[i].fd, response_packet);
                        delete_fd(i, &fds, &nfds);
                        free_packet(response_packet);
                        free(response_header);
                        continue;
                    }
                    
                    // Check the cache
                    dns_packet_t *cache_entry = get_cache_entry(cache, msg);
                    if (cache_entry){
                        // response exists in cache, so send it back and close connections
                        message_t *response = parse_packet(cache_entry);
                        process_response(response);
                        send_response(fds[i].fd, cache_entry);
                        delete_fd(i, &fds, &nfds);
                        free_message(response);
                        continue;
                    }

                    // Last resort, forward upstream
                    int upstream_fd = forward_packet(argv, packet);
                    fds[i+1].fd = upstream_fd;

                    free_packet(packet);
                    free_message(msg);
                    break;
                } else {
                    // This must be a response from the upstream connection
                    dns_packet_t *response_packet = read_packet(fds[i].fd);
                    close(fds[i].fd);

                    // Process it and send it back to client
                    message_t *response = parse_packet(response_packet);
                    process_response(response);
                    send_response(fds[i-1].fd, response_packet);
                    
                    // Remove the now closed connections from array
                    delete_fd(i-1, &fds, &nfds);
                    free_packet(response_packet);
                    free_message(response);
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