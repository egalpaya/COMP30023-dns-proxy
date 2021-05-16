/*************************************************************************************************/           
/*  COMP30023 Assignment 2                                                                       */
/*  Eishitha Galpayage Don                                                                       */
/*  993413                                                                                       */
/*  Functions/structs to implement caching                                                       */
/*************************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <string.h>
#include <arpa/inet.h>
#include "cache.h"
#include "parser.h"
#include "utils.h"

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

/*  Adds the given response and packet to the cache, kicking out the entry with lowest TTL  */
void add_cache_entry(cache_t *cache, message_t *response, dns_packet_t *packet){

    cache_entry_t *entry = (cache_entry_t *)malloc(sizeof(cache_entry_t));
    assert(entry);

    entry->response = response;
    entry->packet = packet;
    
    time_t curr_time;
    time(&curr_time);
    entry->last_accessed = curr_time;

    if (cache->num_items < CACHE_SIZE){

        cache->entries[cache->num_items++] = entry;
        return;
    }

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

    // kick it out
    cache_entry_t *old_entry = cache->entries[index];
    cache->entries[index] = entry;

    // write to log
    char buf[MAX_LOG_ENTRY];
    char name1[MAX_DNAME_CHARS], name2[MAX_DNAME_CHARS];
    strcpy(name1, old_entry->response->questions[0]->qname);
    strcpy(name2, entry->response->questions[0]->qname);
    remove_trailing_dot(name1);
    remove_trailing_dot(name2);
    snprintf(buf, MAX_LOG_ENTRY, "replacing %s by %s\n", name1, name2);
    write_log(buf);

    free_message(old_entry->response);
    free_packet(old_entry->packet);
    free(old_entry);
}

/*  Updates the TTL and last accessed time of the first answer of the given cache entry. */
void update_ttl(cache_entry_t *entry){

    time_t curr_time;
    time(&curr_time);
    double diff = difftime(curr_time, entry->last_accessed);
    entry->last_accessed = curr_time;

    // avoid issues with unsigned ints
    if (entry->response->answers[0]->ttl < diff){
        entry->response->answers[0]->ttl = 0;
    } else {
        entry->response->answers[0]->ttl -= diff;
    }
}

/*  Checks whether the given query has a valid answer record in the cache, determined by comparing 
    the first question of the records. Returns the packet if it exists, else returns null */
dns_packet_t *get_cache_entry(cache_t *cache, message_t *query){

    dns_packet_t *response_packet = NULL;

    for (int i = 0; i < cache->num_items; i++){
        
        if (compare_questions(query->questions[0], cache->entries[i]->response->questions[0])
            && cache->entries[i]->response->answers[0]->ttl > 0){
            // matching, valid record exists
       
            // replace ID
            cache->entries[i]->response->header->id = query->header->id;
            update_ttl(cache->entries[i]);

            // generate response packet
            response_packet = create_packet(cache->entries[i]->response);

            // swap with old
            dns_packet_t *old_packet = cache->entries[i]->packet;
            cache->entries[i]->packet = response_packet;
            free_packet(old_packet);

            // write to log
            char buf[MAX_LOG_ENTRY];
            char name[MAX_DNAME_CHARS];
            char timestamp[MAX_TIMESTAMP_LEN];
            time_t curr_time;
            time(&curr_time);
            get_timestamp(timestamp, curr_time + cache->entries[i]->response->answers[0]->ttl);
            strcpy(name, cache->entries[i]->response->questions[0]->qname);
            remove_trailing_dot(name);
            snprintf(buf, MAX_LOG_ENTRY, "%s expires at %s\n", name, timestamp);
            write_log(buf);
            break;
        }
    }

    return response_packet;
}

/*  Compares two questions, returns 1 if they are identical, 0 otherwise   */
int compare_questions(question_t *q1, question_t *q2){

    return ((strcmp(q1->qname, q2->qname) == 0) && 
            (q1->qtype == q2->qtype) && 
            (q1->qclass == q2->qclass));
}

void print_cache(cache_t *cache){
    printf("printing cache...\n");
    for (int i = 0; i < cache->num_items; i++){
        print_message(cache->entries[i]->response);
    }
}