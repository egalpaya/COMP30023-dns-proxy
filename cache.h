/*************************************************************************************************/           
/*  COMP30023 Assignment 2                                                                       */
/*  Eishitha Galpayage Don                                                                       */
/*  993413                                                                                       */
/*  Functions/structs to implement caching                                                       */
/*************************************************************************************************/
#ifndef CACHE_H
#define CACHE_H

#include <time.h>
#include "utils.h"

typedef struct cache cache_t;
typedef struct cache_entry cache_entry_t;

struct cache_entry {
    message_t *response;
    dns_packet_t *packet;
    time_t arrival_time;
};

struct cache {
    // A queue would probably be better but an array will suffice for small cache sizes
    cache_entry_t **entries;
    int num_items;
};

/*  Initialise cache, returning the struct  */
cache_t *create_cache();

/*  Adds the given response and packet to the cache, kicking out the "most expired entry",
    defined by the lowest time to live (updated to reflect current time) */
void add_cache_entry(cache_t *cache, message_t *response, dns_packet_t *packet);

/*  Returns the updated TTL of the first answer of the given cache entry. If the returned value
    is -ve, the record has expired. */
int get_ttl(cache_entry_t *entry);

/*  Checks whether the given query has a valid answer record in the cache, determined by comparing 
    the first question of the records. Returns the packet if it exists, else returns null */
dns_packet_t *get_cache_entry(cache_t *cache, message_t *query);

/*  Compares two questions, returns 1 if they are identical, 0 otherwise   */
int compare_questions(question_t *q1, question_t *q2);


#endif