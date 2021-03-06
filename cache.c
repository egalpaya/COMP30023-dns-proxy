/*************************************************************************************************/           
/*  COMP30023 Assignment 2                                                                       */
/*  Eishitha Galpayage Don                                                                       */
/*  993413                                                                                       */
/*  Functions/structs to implement caching                                                       */
/*************************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>

#include "parser.h"
#include "cache.h"

#define CACHE_SIZE 5

/*  Initialise cache, returning the struct  */
cache_t *create_cache(){

    cache_t *cache = (cache_t *)malloc(sizeof(cache_t));
    assert(cache);

    cache->entries = (cache_entry_t **)malloc(sizeof(cache_entry_t *)*CACHE_SIZE);
    assert(cache);

    cache->num_items = 0;

    return cache;
}

/*  Adds the given response to the cache, kicking out the entry with lowest TTL  */
void add_cache_entry(cache_t *cache, message_t *response){

    cache_entry_t *entry = (cache_entry_t *)malloc(sizeof(cache_entry_t));
    assert(entry);

    entry->response = response;
    
    time_t curr_time;
    time(&curr_time);
    entry->last_accessed = curr_time;

    // find the lowest TTL entry (or first one with 0 TTL)
    int lowest_ttl = INT_MAX;
    int index = -1;
    for (int i = 0; i < cache->num_items; i++){
        
        update_ttl(cache->entries[i]);

        if (cache->entries[i]->response->answers[0]->ttl < lowest_ttl){
            lowest_ttl = cache->entries[i]->response->answers[0]->ttl;
            index = i;
        }
    }

    if (lowest_ttl != 0 && cache->num_items < CACHE_SIZE){
        // there is free space in cache and none of the entries are expired, so just add it
        cache->entries[cache->num_items++] = entry;
        return;
    }
    
    // kick out the expired or lowest ttl entry
    cache_entry_t *old_entry = cache->entries[index];
    cache->entries[index] = entry;

    log_cache_eviction(entry, old_entry);
    free_message(old_entry->response);
    free(old_entry);
}

/*  Writes a cache eviction to log  */
void log_cache_eviction(cache_entry_t *new_entry, cache_entry_t *old_entry){

    char buffer[MAX_LOG_ENTRY];
    char old_name[MAX_DNAME_CHARS], new_name[MAX_DNAME_CHARS];

    strcpy(old_name, old_entry->response->questions[0]->qname);
    strcpy(new_name, new_entry->response->questions[0]->qname);
    remove_trailing_dot(old_name);
    remove_trailing_dot(new_name);
    snprintf(buffer, MAX_LOG_ENTRY, "replacing %s by %s\n", old_name, new_name);
    write_log(buffer);
}

/*  Updates the TTL and last accessed time of the first answer of the given cache entry. */
void update_ttl(cache_entry_t *entry){

    time_t curr_time;
    time(&curr_time);
    double diff = difftime(curr_time, entry->last_accessed);
    entry->last_accessed = curr_time;

    // decrement ttl, bounded at 0 to avoid issues with unsigned ints
    if (entry->response->answers[0]->ttl < diff){
        entry->response->answers[0]->ttl = 0;
    } else {
        entry->response->answers[0]->ttl -= diff;
    }
}

/*  Checks whether the given query has a valid answer record in the cache, determined by comparing 
    the first question of the records. Returns the packet if it exists, else returns null */
packet_t *get_cache_entry(cache_t *cache, message_t *query){

    packet_t *response_packet = NULL;
    
    for (int i = 0; i < cache->num_items; i++){
        
        update_ttl(cache->entries[i]);

        if (compare_questions(query->questions[0], cache->entries[i]->response->questions[0])
            && cache->entries[i]->response->answers[0]->ttl > 0){
            // matching, valid record exists

            // replace ID
            cache->entries[i]->response->header->id = query->header->id;

            // generate response packet
            response_packet = create_packet(cache->entries[i]->response);

            log_cache_access(cache->entries[i]);
            break;
        }
    }

    return response_packet;
}

/*  Logs an accessed cache entry    */
void log_cache_access(cache_entry_t *entry){

    char buffer[MAX_LOG_ENTRY];
    char name[MAX_DNAME_CHARS];
    char timestamp[MAX_TIMESTAMP_LEN];
    time_t curr_time;

    time(&curr_time);
    get_timestamp(timestamp, curr_time + entry->response->answers[0]->ttl);
    strcpy(name, entry->response->questions[0]->qname);
    remove_trailing_dot(name);
    snprintf(buffer, MAX_LOG_ENTRY, "%s expires at %s\n", name, timestamp);
    write_log(buffer);
}

/*  Compares two questions, returns 1 if they are identical, 0 otherwise   */
int compare_questions(question_t *q1, question_t *q2){

    return ((strcmp(q1->qname, q2->qname) == 0) && 
            (q1->qtype == q2->qtype) && 
            (q1->qclass == q2->qclass));
}

/*  Frees all memory associated with cache  */
void free_cache(cache_t *cache){

    for (int i = 0; i < cache->num_items; i++){
        free_message(cache->entries[i]->response);
        free(cache->entries[i]);
    }
    free(cache->entries);
    free(cache);
}

/*  Prints cache entries - for testing purposes */
void print_cache(cache_t *cache){

    printf("printing cache...\n");
    for (int i = 0; i < cache->num_items; i++){
        print_message(cache->entries[i]->response);
    }
}