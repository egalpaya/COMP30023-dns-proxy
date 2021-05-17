/*************************************************************************************************/           
/*  COMP30023 Assignment 2                                                                       */
/*  Eishitha Galpayage Don                                                                       */
/*  993413                                                                                       */
/*  Functions/structs to implement caching                                                       */
/*************************************************************************************************/
#ifndef CACHE_H
#define CACHE_H

#include "utils.h"

typedef struct cache cache_t;
typedef struct cache_entry cache_entry_t;

struct cache_entry {
    message_t *response;
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

/*  Adds the given response to the cache, kicking out the entry with lowest TTL  */
void add_cache_entry(cache_t *cache, message_t *response);

/*  Writes a cache eviction to log  */
void log_cache_eviction(cache_entry_t *new_entry, cache_entry_t *old_entry);

/*  Updates the TTL and last accessed time of the first answer of the given cache entry. */
void update_ttl(cache_entry_t *entry);

/*  Checks whether the given query has a valid answer record in the cache, determined by comparing 
    the first question of the records. Returns the packet if it exists, else returns null */
packet_t *get_cache_entry(cache_t *cache, message_t *query);

/*  Logs an accessed cache entry    */
void log_cache_access(cache_entry_t *entry);

/*  Compares two questions, returns 1 if they are identical, 0 otherwise   */
int compare_questions(question_t *q1, question_t *q2);

/*  Frees all memory associated with cache  */
void free_cache(cache_t *cache);

/*  Prints cache entries - for testing purposes */
void print_cache(cache_t *cache);

#endif