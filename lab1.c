/* lab1.c 
 * Huzefa Dossaji                
 * hdossaj                     
 * ECE 223 Fall 2015
 * MP1
 *
 * NOTE:  You must update all of the following comments!
 *
 * Purpose: CONTAINS THE MAIN() FUNCTION, MENU CODE FOR HANDLING SIMPLE INPUT AND OUTPUT USED TO TEST OUT ADT, AND ANY OTHER FUNCTONS THAT ARE NOT PART OF THE ADT
 *
 * Assumptions:  User will give all values with valid values. 
 * The program accepts one command line arguement that is the size of the list.
 *
 * An outline for the interactive menu input is provided.  Details need to be
 * completed but the format of the commands and the prints found in 
 * hpot_record_fill hpot_print_rec should not be changed.
 *
 * Bugs: NO BUGS HAVE BEEN SEEN IN THIS PROGRAM WITH MY EXTENSIVE TESTING. 
 *
 * See the ECE 223 programming guide
 *
 * NOTE: if it forbidden to access any of the members in the honeypot_t
 * structure.   The member names MUST NOT be found in this file or it is a 
 * design violation.  Instead you must utilize the honeypot_ fuctions found 
 * in the honeypot header file to access any details of the list.
 *
 * One of the requirements is to verify you program does not have any 
 * memory leaks or other errors that can be detected by valgrind.  Run with
 * your test scripts:
 *      valgrind --leak-check=full ./lab1 < your_test_script
 * 
 * Are you unhappy with the way this code is formatted?  You can easily
 * reformat (and automatically indent) your code using the astyle 
 * command.  If it is not installed use the Ubuntu Software Center to 
 * install astyle.  Then in a terminal on the command line do
 *     astyle --style=kr lab1.c
 *
 * See "man astyle" for different styles.  Replace "kr" with one of
 * ansi, java, gnu, linux, or google to see different options.  Or, set up 
 * your own style.
 *
 * To create a nicely formated PDF file for printing install the enscript 
 * command.  To create a PDF for "file.c" in landscape with 2 columns do:
 *     enscript file.c -G2rE -o - | ps2pdf - file.pdf
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "honeypot.h"

int main(int argc, char **argv)
{
// THESE ARE STRUCTURES DECLARATIONS POINTERS FOR BOTH PACKET T AND HONEYPOT. NO MEMBERS OF HONEYPOT WERE ACCESSED
    struct packet_t *new_rec=NULL;
    struct packet_t *dup_rec=NULL;
    struct honeypot_t *list_add=NULL; 
    
    
    
    
    char line[MAXLINE];
    char command[MAXLINE];
    char junk[MAXLINE];
    int num_items;
    int ip_add;
    int index;
    int list_size;

    if (argc != 2) {
        printf("Usage: ./lab1 list_size\n");
        exit(1);
    }
    list_size = atoi(argv[1]);
    if (list_size < 1) {
        printf("lab1 has invalid list size: %d\n", list_size);
        exit(2);
    }
    
    list_add = hpot_construct(list_size);
    
    printf("Welcome to lab1. Using list size: %d\n", list_size);
    printf("INSERT x\nLIST x\nREMOVE x\nSCAN x\nPRINT\nQUIT\n");
    
// THIS WHILE LOOP ALLOWS THE USER TO INPUT COMMANDS SUCH AS "INSERT, LIST, REMOVE, SCAN, PRINT AND QUIT" 
// THE QUIT COMMAND FREES ALL THE DYNAMIC MEMORY AND ENDS THE PROGRAM
    // remember fgets includes newline \n unless line too long
    while (fgets(line, MAXLINE, stdin) != NULL) {
        num_items = sscanf(line, "%s%d%s", command, &ip_add, junk);
        if (num_items == 1 && strcmp(command, "QUIT") == 0) {
            hpot_destruct(list_add);
            
            /* found exit */
            printf("cleanup\n");
            break;
        } else if (num_items == 2 && strcmp(command, "INSERT") == 0) {         
            new_rec = (struct packet_t *) malloc(sizeof(struct packet_t));
            
            // WHEN INSERT IS INPUTTED WITH A NUMBER, THE FILL COMMAND IS CALLED FILLING UP A SPECIFIC STRUCTURES WITH THE INPUTTED DATA
            hpot_record_fill(new_rec);
            new_rec->dest_ip_addr = ip_add;
 
        // THE ADD FUNCTION IS CALLED TO PUT THE NEW DATA STRUCTURE INTO A LIST OF DATA STRUCTURES IN NUMERICAL ORDER
            int add_return = hpot_add(list_add, new_rec);

            if (add_return == 1) {
                printf("\nAdded: %d and doubled list size\n",ip_add);
            } else if (add_return == 0) {
                printf("\nAdded: %d\n",ip_add);
            } else {
                printf("\n\nError with hpot_add return value\n");
                exit(1);
            }
            
            //new_rec = NULL;
        } else if (num_items == 2 && strcmp(command, "LIST") == 0) {
            // THE LIST COMMAND MUST PRINT THE INFORMATION FOR EACH PACKET FOR WHICH THE DEST_IP_ADDR MATCHES THE INPUTTED IP_ADDRESS
            int same = 1;
            index = 0;
            int x=1;
           
            same = hpot_lookup(list_add, ip_add);
            new_rec = hpot_access(list_add, same);   // FIXED
            if(same != -1){
            hpot_print_rec(new_rec);
            }
            int num_count = hpot_count(list_add);
            
            index++;
            

            if (same == -1) {
                printf("Did not find: %d\n", ip_add);
            } else {
                
                while((new_rec->dest_ip_addr == ip_add) && ((same + x) < num_count)){
                    same = hpot_lookup(list_add, ip_add);
                    
                    new_rec = hpot_access(list_add, same+x);   // FIXED
                    
                    if(new_rec->dest_ip_addr == ip_add){
                    hpot_print_rec(new_rec);
                   
                    index++;
                    
                    }
                    x++;
                }
                
                
                // index: how many packets match ip_add
                printf("Found %d packets matching %d\n", index, ip_add);
            }
            
            new_rec = NULL;
        //THE REMOVE COMMAND REMOVES ALL THE CORRESPONDING RECORDS FROM THE LIST, FREES THE MEMORY
        } else if (num_items == 2 && strcmp(command, "REMOVE") == 0) {
            int ind =0;
            index =0;
            
            
            ind=hpot_lookup(list_add, ip_add);   // I THINK FIXED
              
            new_rec = hpot_remove(list_add, ind);
            free(new_rec);
            if(new_rec != NULL){
                index++;
            }
            
            if (new_rec == NULL) {
                printf("Did not remove: %d\n", ip_add);
            } else {
                while(new_rec != NULL){
                    ind=hpot_lookup(list_add, ip_add);   //loop to eliminate all instances of ip_add in the list
                       if(ind !=-1){
                    new_rec = hpot_remove(list_add, ind);
                    free(new_rec);
                    index++;
                    }
                    else 
                    break;
                        
                   }
                printf("Removed %d packets matching %d\n", index, ip_add);
                // But, do not print each packet
            }
            // THE SCAN COMMANDS SEARCHES THE LIST FOR ALL SETS OF PACKETS FOR WHICH THERE ARE THRESHOLD OR MORE 
            // PACKET RECORDS WITH THE SAME DEST_IP_ADDR. 
        } else if (num_items == 2 && strcmp(command, "SCAN") == 0) {
            index = 0;
            int groups = 0;
            int match = 0;
            int match_temp=0;
            int print = 0;
            int threshold = ip_add;
            int x=0;
            int j=1;
           
            int count=hpot_count(list_add);
            
            if(count != 0){
            do{
                count = hpot_count(list_add);
                new_rec=hpot_access(list_add, x);
                
                
                
                dup_rec=hpot_access(list_add, j);
                
                
               
                if(new_rec->dest_ip_addr == dup_rec->dest_ip_addr){
                        match++;
                }
                else
                {
                    x=j;
                    
                    match_temp=match+1;
                    match=0;
                }  
                
                if(match_temp >= threshold){
                    
                    print=1;
                 }
                
                if((print==1) && (match==0)){
                   printf("A set with address %d has %d packets\n", new_rec->dest_ip_addr, match_temp);
                   
                   print = 0;
                   groups++;
                }
                j++;
                
                
                if((j==count) && ((match+1)>=threshold)){
                    match_temp=match+1;
                    if((threshold == 1) && (match_temp == 1)){
                        printf("A set with address %d has %d packets\n", dup_rec->dest_ip_addr, match_temp);
                        groups++;
                        break;
                    }   
                    
                    
                    printf("A set with address %d has %d packets\n", new_rec->dest_ip_addr, match_temp);
                                       
                    groups++;
                    print=0;
                    
                }
            }while(((new_rec != NULL) || (dup_rec != NULL)) && (x < count) && (j<count));
            }
            
           x=0;
           j=1; 
            
          
       
            if (groups > 0) {
                printf("Found %d sets\n", groups);
            } else {
                printf("No records with >= %d matches\n", ip_add);
            }
            
            // THE PRINT COMMAND JUST PRINTS THE ENTIRE LIST IN NUMERICAL ORDER
        } else if (num_items == 1 && strcmp(command, "PRINT") == 0) {
            int num_in_list = hpot_count(list_add);     // FIXED
             
            if (num_in_list == 0) {
                printf("List empty\n");
            } else {
                printf("List has %d records\n", num_in_list);
                int i;
                for (i = 0; i < num_in_list; i++) {
                    printf("%d: ", i+1);
                    // you must use this function to format output for a record
                    new_rec = hpot_access(list_add,i);   // FIXED
                    
                    hpot_print_rec(new_rec);              
                    
                }
            }
           
        } else {
            printf("# %s", line);
        }
    }
   
    
    
    exit(0);
}

/* commands specified to vim. ts: tabstop, sts: soft tabstop sw: shiftwidth */
/* vi:set ts=8 sts=4 sw=4 et: */
