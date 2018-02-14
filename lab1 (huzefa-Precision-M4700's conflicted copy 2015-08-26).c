/* lab1.c 
 * Huzefa Dossaji                <<-- replace with your name!
 * hdossaj                      <<-- replace with your user name!
 * ECE 223 Fall 2015
 * MP1
 *
 * NOTE:  You must update all of the following comments!
 *
 * Purpose: A template for MP1 
 *
 * Assumptions: Many details are incomplete.  The functions to collect input
 * for a record and to print a record specify the format that is required for
 * grading.
 *
 * The program accepts one command line arguement that is the size of the list.
 *
 * An outline for the interactive menu input is provided.  Details need to be
 * completed but the format of the commands and the prints found in 
 * hpot_record_fill hpot_print_rec should not be changed.
 *
 * Bugs: Many detail have not been implemented.
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
    struct packet_t *new_rec;
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
    printf("Welcome to lab1. Using list size: %d\n", list_size);
    printf("INSERT x\nLIST x\nREMOVE x\nSCAN x\nPRINT\nQUIT\n");

    // remember fgets includes newline \n unless line too long
    while (fgets(line, MAXLINE, stdin) != NULL) {
        num_items = sscanf(line, "%s%d%s", command, &ip_add, junk);
        if (num_items == 1 && strcmp(command, "QUIT") == 0) {
            /* found exit */
            printf("cleanup\n");
            break;
        } else if (num_items == 2 && strcmp(command, "INSERT") == 0) {         
            new_rec = (struct packet_t *) malloc(sizeof(struct packet_t));
            hpot_record_fill(new_rec);
            new_rec->dest_ip_addr = ip_add;
           
            
                //hpot_add(list, new_rec);
 
            // you have to figure out what goes here
            // and call the correct printf command
            int add_return = -3;

            if (add_return == 1) {
                printf("\nAdded: %d and doubled list size\n",ip_add);
            } else if (add_return == 0) {
                printf("\nAdded: %d\n",ip_add);
            } else {
                printf("\n\nError with hpot_add return value\n");
                exit(1);
            }
            new_rec = NULL;
        } else if (num_items == 2 && strcmp(command, "LIST") == 0) {
            new_rec = NULL;   // fix

            if (new_rec == NULL) {
                printf("Did not find: %d\n", ip_add);
            } else {
                // First, you must print each of the matching packets 
                hpot_print_rec(new_rec);
                // Then print a summary stating how many were found
                // index: how many packets match ip_add
                printf("Found %d packets matching %d\n", index, ip_add);
            }
            new_rec = NULL;
        } else if (num_items == 2 && strcmp(command, "REMOVE") == 0) {
            new_rec = NULL;   // fix

            if (new_rec == NULL) {
                printf("Did not remove: %d\n", ip_add);
            } else {
                printf("Removed %d packets matching %d\n", index, ip_add);
                // But, do not print each packet
            }
        } else if (num_items == 2 && strcmp(command, "SCAN") == 0) {
            index = 0;
            int groups = 0;
            // for each group that is removed print how many removed
            printf("A set with address %d has %d packets\n", num_items, index);
            // after all sets have been removed print how many sets
            if (groups > 0) {
                printf("Found %d sets\n", groups);
            } else {
                printf("No records with >= %d matches\n", ip_add);
            }
        } else if (num_items == 1 && strcmp(command, "PRINT") == 0) {
            int num_in_list = 0;     // fix!
            if (num_in_list == 0) {
                printf("List empty\n");
            } else {
                printf("List has %d records\n", num_in_list);
                int i;
                for (i = 0; i < num_in_list; i++) {
                    printf("%d: ", i+1);
                    // you must use this function to format output for a record
                    new_rec = NULL;   // fix
                    hpot_print_rec(new_rec);
                }
            }
            new_rec = NULL;
        } else {
            printf("# %s", line);
        }
    }
    exit(0);
}

/* commands specified to vim. ts: tabstop, sts: soft tabstop sw: shiftwidth */
/* vi:set ts=8 sts=4 sw=4 et: */
