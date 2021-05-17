/*************************************************************************************************/           
/*  COMP30023 Assignment 2                                                                       */
/*  Eishitha Galpayage Don                                                                       */
/*  993413                                                                                       */
/*  Main function                                                                                */
/*************************************************************************************************/
#include <stdio.h>
#include <stdlib.h>

#include "server.h"

#define CACHE
#define NONBLOCKING

int main(int argc, char **argv){

    if (argc != 3){
        printf("usage: dns_svr [upstream_server_ip] [port]\n");
        exit(EXIT_FAILURE);
    }

    run_server(argv);

}