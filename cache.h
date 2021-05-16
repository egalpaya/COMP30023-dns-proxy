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
    time_t last_accessed;
    int ttl;
};

struct cache {
    // A queue would probably be better but an array will suffice for small cache sizes
    cache_entry_t **entries;
    int num_items;
};

/*  Initialise cache, returning the struct  */
cache_t *create_cache();

/*  Adds the given response and packet to the cache, kicking out the entry with lowest TTL  */
void add_cache_entry(cache_t *cache, message_t *response, dns_packet_t *packet);

/*  Updates the TTL and last accessed time of the first answer of the given cache entry. */
void update_ttl(cache_entry_t *entry);

/*  Checks whether first question of query has a valid answer record in the cache.
    If it exists, returns associated packet, else returns null */
dns_packet_t *get_cache_entry(cache_t *cache, message_t *query);

/*  Compares two questions, returns 1 if they are identical, 0 otherwise   */
int compare_questions(question_t *q1, question_t *q2);

void print_cache(cache_t *cache);


#endif