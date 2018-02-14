/* honeypot.c template
 * Prof. Russell        <<-- you must change these details!
 * ECE 223 Fall 2015
 * MP1
 *
 * Purpose: A template for MP1 
 *
 * Assumptions: Many details are incomplete.  The functions to collect input
 * for a record and to print a record specify the format that is required for
 * grading.
 *
 * Bugs: Many detail have not been implemented.
 *
 * See the ECE 223 programming guide
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "honeypot.h"

struct honeypot_t *hpot_construct(int size)
{
  
    struct honeypot_t *ptr;
    int i;
    
    ptr=(struct honeypot_t *)malloc (sizeof(struct honeypot_t));
    ptr->pot_size = size;
    
    ptr->hpot_ptr = (struct packet_t **) malloc(size* sizeof(struct packet_t *));
    for(i=0; i<size; i++)
        ptr->hpot_ptr[i]=NULL;
    return ptr;
}

void hpot_destruct(struct honeypot_t *list)
{
    int i;
    for(i=0; i<list->pot_size; i++)
    {
        free(list->hpot_ptr[i]);
        list->hpot_ptr[i] = NULL;
    }
    free(list->hpot_ptr);
    list->hpot_ptr = NULL;
    free(list);
    list = NULL;
}

int hpot_add(struct honeypot_t *list, struct packet_t *rec_ptr)
{
 int i=0;

 
    if(list->hpot_ptr[i] == NULL){
    list->hpot_ptr[i] = rec_ptr;
    i++;
    
    printf("Done 1\n");
    printf("i = %d\n", i);
    }
    else if(rec_ptr->dest_ip_addr < list->hpot_ptr[pot_entries]->dest_ip_addr){
       int a = pot_entries;
       while(rec_ptr->dest_ip_addr < list->hpot_ptr[a]->dest_ip_addr){
       list->hpot_ptr[a]->dest_ip_addr    // you are right here and you are trying to sort the list while adding the new block and decrement the the biggers ones down
            a--; 
       }
       list->hpot_ptr[a] = rec_ptr;
    }
    
    printf("Done 2\n");
    printf("a = %d\n", a);
    }
    else{
        list->hpot_ptr[list->pot_entries] = rec_ptr;
   
        printf("Done 3");
      
        }
    
    list->pot_entries++;
    
    
    
   
    return 1;
}

int hpot_lookup(struct honeypot_t *list, int addr)
{
    return -1;
}

struct packet_t *hpot_access(struct honeypot_t *list, int index)
{
    return NULL;
}

struct packet_t *hpot_remove(struct honeypot_t *list, int index)
{
    return NULL;
}

int hpot_empty(struct honeypot_t *list)
{
    return -1;
}

int hpot_count(struct honeypot_t *list)
{
    return -1;
}

/* Prompts user for honeypot record input starting with the source IP address.
 * The input is not checked for errors but will default to an acceptable value
 * if the input is incorrect or missing.
 *0
 * The input to the function assumes that the structure has already been
 * created.  The contents of the structure are filled in.
 *
 * There is no output.
 *
 * Do not change the sequence of prompts as grading requires this exact
 * format
 */
void hpot_record_fill(struct packet_t *new)
{
    char line[MAXLINE];
    assert(new != NULL);

    printf("Source IP address:");
    fgets(line, MAXLINE, stdin);
    sscanf(line, "%d", &new->src_ip_addr);
    printf("Destination port number:");
    fgets(line, MAXLINE, stdin);
    sscanf(line, "%d", &new->dest_port_num);
    printf("Source port number:");
    fgets(line, MAXLINE, stdin);
    sscanf(line, "%d", &new->src_port_num);
    printf("Hop count:");
    fgets(line, MAXLINE, stdin);
    sscanf(line, "%d", &new->hop_count);
    printf("Protocol:");
    fgets(line, MAXLINE, stdin);
    sscanf(line, "%d", &new->protocol);
    printf("Threat Score:");
    fgets(line, MAXLINE, stdin);
    sscanf(line, "%f", &new->threat_score);
    printf("Time:");
    fgets(line, MAXLINE, stdin);
    sscanf(line, "%d", &new->time_received);
    printf("\n");
    
}

/* print the information for a particular record 
 *
 * Input is a pointer to a record, and no entries are changed.
 *
 * Do not change any of these lines and grading depends on this
 * format.
 */
void hpot_print_rec(struct packet_t *rec)
{
    assert(rec != NULL);
    printf("Dest IP: %d, Src: %d, Dest port: %d,", rec->dest_ip_addr, 
            rec->src_ip_addr, rec->dest_port_num);
    printf(" Src: %d, Hop Count: %d", rec->src_port_num, rec->hop_count); 
    printf(" Prot: %d", rec->protocol);
    printf(" Score: %g, Time: %d\n", rec->threat_score, rec->time_received);
}


/* commands specified to vim. ts: tabstop, sts: soft tabstop sw: shiftwidth */
/* vi:set ts=8 sts=4 sw=4 et: */
