/* 

   Writing and debugging MP2 is challenging, and it is particularly hard if you
   try and write all the code before you do any testing. It is much easier to
   break the problem into small pieces and test each piece. 

For MP2, one approach is to write list_insert first, since it might be the
easiest algorithm and it depends only on list_construct.

   For testing, we use a simple main function in this file.  This file is for
   testing only, and you will NOT submit it as it is for your personal testing
   during development.

Below are a few simple examples that allocates a few structures and inserts
them into a list.

With this file containing a temporary main section, you can compile and run
list.c on its own using 
   gcc -Wall -g testlist.c list.c hpot_support.c -o testlist

The compling command is also found in the provided makefile.  Do
   make testlist

Do this testing before you make ANY changes to hpot_support.c.  The only 
reason we need to compile hpot_support.c is for the hpot_compare function.
The linker needs to find the comp_proc function and it is found in the template
   hpot_support.c file (with no changes) 

*/

#include <stdlib.h>
#include <stdio.h>
#include "datatypes.h"
#include "list.h"
#include "hpot_support.h"

/* prototype for list debug print */
void list_debug_print(list_t *list_ptr);

int main(void)
{
    data_t *datap = NULL;
    data_t *datap2 = NULL;
    data_t *datap3 = NULL;
    
    list_t *Lptr = NULL;
    list_t *Lsortptr = NULL;

    Lptr = list_construct(hpot_compare);

    // create one item to test list_insert
    datap = (data_t *) malloc(sizeof(data_t));
    datap2 = (data_t *) malloc(sizeof(data_t));
    datap3 = (data_t *) malloc(sizeof(data_t));
    datap->dest_ip_addr = 555;
    datap2->dest_ip_addr=444;
    datap3->dest_ip_addr=333;
    list_insert(Lptr, datap, list_iter_first(Lptr));
    list_insert(Lptr, datap2, list_iter_first(Lptr));
    list_insert(Lptr, datap3, list_iter_tail(Lptr));
    
    
    datap = NULL;

    // test list_access with one item in list
    datap = list_access(Lptr, list_iter_first(Lptr));
    printf("Should find 444 and found (%d)\n\n", datap->dest_ip_addr);
    datap = NULL;

    // add a second item to tail of the list
    datap = (data_t *) malloc(sizeof(data_t));
    datap->dest_ip_addr = 444;
    list_insert(Lptr, datap, list_iter_tail(Lptr));
    datap = NULL;

    // add a third item
    datap = (data_t *) malloc(sizeof(data_t));
    datap->dest_ip_addr = 500;
    list_insert(Lptr, datap, list_iter_tail(Lptr));
    datap = NULL;


    // Test use of pIterator find all three and print 
    pIterator my_index;
    my_index = list_iter_first(Lptr);

    datap = list_access(Lptr, my_index); 
    printf("Second test\nPosition 0 should find 444 and found (%d)\n", datap->dest_ip_addr);
    my_index = list_iter_next(my_index);
    datap = list_access(Lptr, my_index);
    printf("Position 1 should find 555 and found (%d)\n", datap->dest_ip_addr);
    my_index = list_iter_next(my_index);
    datap = list_access(Lptr, my_index);
    printf("Position 2 should find 333 and found (%d)\n", datap->dest_ip_addr);

    //Next try to use list_debug_print 
    printf("\nTest of list print\n\n");
    list_debug_print(Lptr);


    
    datap = (data_t *) malloc(sizeof(data_t));
    datap->dest_ip_addr = 444;
    my_index = list_elem_find(Lptr, datap);
    data_t *foundp = list_access(Lptr, my_index);
    printf("\nTest of list elem find\n");
    if (my_index != NULL)
        printf("looked for %d and found %d\n",
            datap->dest_ip_addr, foundp->dest_ip_addr);
    else
        printf("looked for %d and did not find \n", datap->dest_ip_addr);
    free(datap);  // but not foundp
    datap = foundp = NULL;

   
    Lsortptr = list_construct(hpot_compare);

    datap = (data_t *) malloc(sizeof(data_t));
    datap->dest_ip_addr = 23;
    list_insert_sorted(Lsortptr, datap);
    datap = NULL;

    // add a second item
    datap = (data_t *) malloc(sizeof(data_t));
    datap->dest_ip_addr = 7;
    list_insert_sorted(Lsortptr, datap);
    datap = NULL;

    // add a third item
    datap = (data_t *) malloc(sizeof(data_t));
    datap->dest_ip_addr = 15;
    list_insert_sorted(Lsortptr, datap);
    datap = NULL;

    //Next try to use list_debug_print 
    printf("\nHere is the sorted list\n\n");
    list_debug_print(Lsortptr);

    list_destruct(Lptr);
    list_destruct(Lsortptr);

    return 0;
}

/*

Next you will want to write your own list_debug_print function to print a
list. Then you can do "before and after" testing. That is, print the list
before a change, and print the list after the change to verify that the
change worked.

Something like

*/

void list_debug_print(list_t *list_ptr) {
    llist_node_t *L;
    int count;

    printf("List size: %d\n", list_ptr->llist_size);
    L = list_ptr->llist_head->next;
    count = 0;
    while(L != list_ptr->llist_tail) {
        printf("Pos: %d contains IP: %d\n", count, L->data_ptr->dest_ip_addr);
        L = L->next;
        count++;
    }
    if (count != list_ptr->llist_size)
        printf("Hey!! the list size is wrong! count is %d\n", count);
}

