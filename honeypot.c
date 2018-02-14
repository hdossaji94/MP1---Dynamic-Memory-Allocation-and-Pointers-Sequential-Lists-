/* honeypot.c template
 * HUZEFA DOSSAJI        
 * ECE 223 Fall 2015
 * MP1
 *
 * Purpose: CONTAINS THE ADT CODE FOR OUT SEQUENTIAL LIST. THE MAIN PROGRAM CALLS ON THIS TO ACCESS THE FUNCTIONS
 *
 * Assumptions: User will give all values with valid values. 
 * Bugs: NO BUGS HAVE BEEN SEEN IN THIS PROGRAM WITH MY EXTENSIVE TESTING.
 *
 * See the ECE 223 programming guide
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "honeypot.h"
// THIS FUNCTION BASICALLY DYNAMICALLY ALLOCATES ANY MEMORY WE NEED. IT TAKES AN INPUTTED SIZE AND MALLOCS ENOUGH MEMORY 
// RETURNS A STRUCT HONEYPOT_T
struct honeypot_t *hpot_construct(int size)
{

      
    struct honeypot_t *ptr;
    int i;
    
    ptr=(struct honeypot_t *)malloc (sizeof(struct honeypot_t));
    ptr->pot_size = size;
    ptr->original_size = size;
    
    ptr->pot_entries =0;
    ptr->hpot_ptr = (struct packet_t **) malloc(size* sizeof(struct packet_t *));
    ptr->hpot_temp = (struct packet_t **) malloc(sizeof(struct packet_t *));
    for(i=0; i<size; i++)
        ptr->hpot_ptr[i]=NULL;
    return ptr;
    
   
    
    
}
// THIS FUNCTION IS CALLED WHEN USER INPUTS QUIT AND FREES ALL MEMORY FROM THE INPUTTED HONEYPOT LIST. 
// THIS FUNCTION DOES NOT RETURN ANYTHING
void hpot_destruct(struct honeypot_t *list)
{
    int i;
    for(i=0; i<list->pot_entries; i++)
    {
        free(list->hpot_ptr[i]);
        list->hpot_ptr[i] = NULL;
        
        
    }
    free(list->hpot_temp);
    
    free(list->hpot_ptr);
    
    
 
    free(list);
    
}
// THIS FUNCTION COMPILES AND SORTS THE INPUTTED STRUCTURES INTO A NEAT LIST. IT ALSO DOUBLES THE SIZE OF THE LIST WHEN NEEDED 
// THIS FUNCTION RETURNS AN INT 1 IF IT IS DOUBLED AND A 0 OTHERWISE
int hpot_add(struct honeypot_t *list, struct packet_t *rec_ptr)
{
 int i=0;
int j;
int a=0;
            
            
        list->pot_entries++;
            //list->hpot_ptr[list->pot_entries-1] = rec_ptr;
              
           

      if(list->pot_entries > list->pot_size){
        list->hpot_ptr = (struct packet_t **) realloc(list->hpot_ptr, (2*(list->pot_size))* (sizeof(struct packet_t *)));
        
        
        a=1;
        list->pot_size = (list->pot_size) *2;
        
        int i;
        for(i = list->pot_entries+1; i<list->pot_size; i++){
            list->hpot_ptr[i] = NULL;
        }
    }
    list->hpot_ptr[list->pot_entries-1] = rec_ptr;


       if(list->pot_entries >=2){
        for (i = 0; i < list->pot_entries-1; i++)
    {
        
        for (j = 0; j < (list->pot_entries-i-1); j++)
        {
        
            if ((list->hpot_ptr[j]->dest_ip_addr > list->hpot_ptr[j + 1]->dest_ip_addr)&&((j+1)<list->pot_entries))
            {

                list->hpot_temp[0] = list->hpot_ptr[j];
                list->hpot_ptr[j] = list->hpot_ptr[j + 1];
                list->hpot_ptr[j + 1] = list->hpot_temp[0];
            }
        }
    }
}
    
    
    
    
    
   
    return a;
}
// THIS FUNCTION TAKES THE INPUTTED IP ADDRESS AND SEARCHES THE LIST FOR A MATCH. ONCE FOUND IT RETURNS THE FIRST INDEX POSITION FOUND. 
// THIS FUNCTION RETURNS AN INT INDEX OF THE PACKET T FOUND OR A -1 IF IT DID NOT FIND ONE
int hpot_lookup(struct honeypot_t *list, int addr)
{
    int x;
    for(x=0; x<list->pot_entries; x++){
        if(list->hpot_ptr[x]->dest_ip_addr==addr)
        {
            return x;

        }   
    }
    return -1;
}
// THIS FUNCTION RETURNS A POINTER TO THE PACKET_T MEMORY BLOCK WHEN GIVEN THE INDEX POSITION. 
// IT TAKES IN THE INDEX POSITION AND THE LIST
struct packet_t *hpot_access(struct honeypot_t *list, int index)
{
    struct packet_t * acc;
    acc = NULL;
    if(index >= 0){
    acc = list->hpot_ptr[index];
    }
    return acc;
}
// THIS FUNCTION RETURNS A POINTER TO THE PACKET_T MEMORY BLOCK THAT IS REMOVED BASED ON THE GIVEN IP ADDRESS. 
// THIS FUNCTION TAKES IN THE INDEX POSITION OF THE PACKET T STRUCTURE IN THE LIST
struct packet_t *hpot_remove(struct honeypot_t *list, int index)
{
    
    
    struct packet_t * rem=NULL;
    
    if(index<0){
        return NULL;
    }
    else{
    rem = list->hpot_ptr[index];
    
 
    
    
    int x;
    for(x=index; x < (list->pot_entries) ;x++){
        if(x==(list->pot_entries-1))
        {
            list->hpot_ptr[x]=NULL;
        }
        else{
        list->hpot_ptr[x] = list->hpot_ptr[x+1];
        }
    }
    
    
    list->pot_entries--;
    int pot_rem_perc = ((list->pot_entries*100)/list->pot_size);
    int pot_after = list->original_size / 2;
    if(pot_rem_perc<20 && (pot_after >= list->original_size) && (list->pot_entries!= 0)){
        list->hpot_ptr = (struct packet_t **) realloc(list->hpot_ptr, .5*list->pot_size* sizeof(struct packet_t *));
       list->pot_size = pot_after;
       
    }   
    return rem;
    }
        
    
    
}
// THIS FUNCTION  JUST CHECK IF THE LIST IS EMPTY OR NOT
// IT RETURNS A 1 IF THE LIST IS EMPOTY AND 0 OTHERWISE
int hpot_empty(struct honeypot_t *list)
{
    int status = 0;
    if(list->pot_entries == 0){
        status = 1;
    }
    
    return status;
}
// THIS FUNCTION RETURNS THE NUMBER OF ENTRIES STORED IN THE SEQUENTIAL LIST
int hpot_count(struct honeypot_t *list)
{
    int n;
    n = list->pot_entries;
    return n;
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
 
 // THIS FUNCTION TAKES IN A PACKET T STRUCTURE AND ADDS THE INPUTTED DATA TO A PARTICULAR STRUCTURE
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
 
 //THIS FUNCITON TAKES A PACKET T STRUCTURE AND PRINTS OUT THE DATA
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
