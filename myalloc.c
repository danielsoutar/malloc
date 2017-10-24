//ID: 140012394
//Date: 20/10/2017
//myalloc.c: a very simple memory library that supports coalescing.

#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>

#include "myalloc.h"

#define BLOCK_FREE 1
#define BLOCK_USED 0

#define BOTH_IN_LIST 1
#define NODE2_NOT_IN_LIST 2

#define ptr_add(ptr, x) ((void*)(ptr) + (x))
#define ptr_sub(ptr, x) ((void*)(ptr) - (x))

#define are_adjacent(a, b) (ptr_add(a, a->size) == b)

typedef struct Header {
    int size;
    unsigned int BLOCK_STATUS : 1;
    unsigned int PREV_STATUS  : 1;
} Header;

typedef struct Footer {
    int size;
} Footer;

typedef struct free_list {
    struct free_list *prev, *next;
} free_list;

const int OVERHEAD = sizeof(Header);
const int BLOCK_SIZE = sizeof(Header) + sizeof(Footer) + sizeof(free_list);
const int MIN_PAYLOAD_SIZE = sizeof(Footer) + sizeof(free_list);


int page_size = 1 << 12;

//one very important implementation detail: we start off with a single self-referential free_list head. We will avoid NULL, but this list head will
//NOT have a header and is separate from the heap space.
free_list base = {
        &base,
        &base
};

const free_list *free_list_head = &base;
free_list *last = &base;

//we always assume that header1 is address-wise prior to header2
//we return a pointer to the first header as the second one is now redundant
Header * coalesce(Header *header1, Header *header2, int caseno) {
    //first update the header: change the size, no change to flags.
    header1->size += header2->size;

    //if both the free_list structs are in the free list, then we need to rearrange the connections to the first.
    //if not, then we don't need to worry about the second - just make sure that the free list pointer is updated to be after the new header once we return.
    free_list *free_list1 = (free_list *)(ptr_add(header1, sizeof(Header)));
    free_list *free_list2 = (free_list *)(ptr_add(header2, sizeof(Header)));

    if(caseno == BOTH_IN_LIST) {
        free_list1->next = free_list2->next;
        free_list1->next->prev = free_list1;
    }

    //finally the footer: update the second one only (the end of the now bigger block)
    Footer *footer2 = (Footer *)ptr_add(header1, header1->size - sizeof(Footer));
    footer2->size = header1->size;

    return header1;
}

void set_region(Header *region, int req_size, int blck_flag, int prev_flag) {
    region->size = req_size;
    region->BLOCK_STATUS = blck_flag;
    region->PREV_STATUS = prev_flag;
}

void set_free_list(free_list *predecessor, free_list *free_pointer, Header *region) {
    //check for opportunity to coalesce: if not, just connect to previous free list
    //if free list head is the predecessor, then the predecessor is external and has no valid header, so we need to check for this.
    Header *prev_block = (Header *)ptr_sub(predecessor, sizeof(Header));
    if(predecessor != free_list_head && ptr_add(prev_block, prev_block->size) == region)
        region = coalesce(prev_block, region, NODE2_NOT_IN_LIST);
    else {
        //set up the free list connections from the preceding node
        free_pointer->next = predecessor->next;
        free_pointer->prev = predecessor;
        predecessor->next = free_pointer;
        free_pointer->next->prev = free_pointer;
    }

    //check for opportunity to coalesce forwards: if not, we already sorted out all of our connections with the previous block, so that's us done.
    free_list *successor = free_pointer->next;
    if(successor != free_list_head) {
        Header *next_block = (Header *)(ptr_sub(successor, sizeof(Header)));
        if(ptr_add(region, region->size) == next_block)
            coalesce(region, next_block, BOTH_IN_LIST);
    }
}

void set_footer(Header *region, int req_size) {
    int payload_size = region->size - sizeof(Footer);
    Footer *end = (Footer *)ptr_add(region, payload_size);
    end->size = req_size;
}

void * allocate_from_region(Header *region, int usr_size) {
    int size = region->size;
    free_list *free_pointer = (free_list *)ptr_add(region, sizeof(Header));

    if(size >= sizeof(Header) + usr_size + BLOCK_SIZE) {
        //we need to partition since we have enough surplus for another block.
        //set up the new header

        Header *new_block = (Header *)ptr_add(region, usr_size + sizeof(Header));
        set_region(new_block, size - sizeof(Header) - usr_size, BLOCK_FREE, BLOCK_USED);

        //revise the header of the block to be used
        region->size -= new_block->size;
        region->BLOCK_STATUS = BLOCK_USED;

        //set up the new free_list pointer, update the free list connections
        free_list *new_pointer = (free_list *)ptr_add(new_block, sizeof(Header));
        new_pointer->prev = free_pointer->prev;
        new_pointer->next = free_pointer->next;
        new_pointer->prev->next = new_pointer;
        new_pointer->next->prev = new_pointer;

        //since we search the free list from the last matched free list, shift that to the next block since it'd be overwritten otherwise.
        //last = new_pointer;

        //set up the new footer
        set_footer(new_block, new_block->size - sizeof(Footer));

        //add one header-sized chunk to the header pointer and return.
        return (void *)(region + 1);
    }
    else {
        //remove free status from this block, update the prev free status from the next block, and rearrange free pointers
        free_pointer->prev->next = free_pointer->next;
        free_pointer->next->prev = free_pointer->prev;

        region->BLOCK_STATUS = BLOCK_USED;

        Header *next_header = (Header *)ptr_add(region, size);
        next_header->PREV_STATUS = BLOCK_USED;

        return (void *)(region + 1);
    }
}

void *myalloc(int size) {
    //if zero or negative memory asked for, go away and stop making stupid requests >:(
    if (size < 1)
        return NULL;

    //needs to be at least the length of the free list and the footer, because that space will be needed once it's freed.
    if(size < MIN_PAYLOAD_SIZE)
        size = MIN_PAYLOAD_SIZE;

    free_list *free_pointer;

    //check free list to see if that satisfies our request on a first-fit basis.
    //however, the clever bit is that we start searching from the last pointer that matched - this promotes BOTH temporal and spatial locality! :)
    for(free_pointer = last; free_pointer != last->prev; free_pointer = free_pointer->next) {
        Header *h = (Header *) ptr_sub(free_pointer, sizeof(Header));
        if(h->size >= size + OVERHEAD)
            return allocate_from_region(h, size);
    }

    //otherwise request memory from kernel - we call this a region. We'll do this in increments of pages. Fewer calls to mmap, simpler. Both good.
    Header *region;
    int req_size = page_size;
    while(req_size < (size + OVERHEAD))
        req_size += page_size;

    region = mmap(NULL, req_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);

    //well if the kernel isn't playing ball, then nothing we can do - fail.
    if(region == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }

    free_pointer = (free_list *)ptr_add(region, sizeof(Header));

    //we order the free list by address, so we'll scan backwards here and get the previous free block.
    free_list *predecessor;
    for(predecessor = free_list_head->prev; predecessor != free_list_head; predecessor = predecessor->prev)
        if(predecessor < free_pointer)
            break;

    set_region(region, req_size, BLOCK_FREE, BLOCK_FREE);
    set_free_list(predecessor, free_pointer, region);
    set_footer(region, req_size);

    //with our freshly-baked memory from the kernel, allocate from it.
    return allocate_from_region(region, size);
}

void myfree(void *ptr){
    //really? Deal with this obvious edge case
    if(!ptr)
        return;

    //need to be very careful - this has no actual pointers yet since this memory was written over! We need to connect it first.
    free_list *free_pointer = ptr;

    //as mentioned before, we order by address, so we'll scan backwards.
    free_list *predecessor;
    for(predecessor = free_list_head->prev; predecessor != free_list_head; predecessor = predecessor->prev)
        if(predecessor < free_pointer)
            break;

    //we only toggle the block flag - not the size. Depends on what happens.
    Header *recovered_header = (Header *)ptr_sub(free_pointer, sizeof(Header));
    recovered_header->BLOCK_STATUS = BLOCK_FREE;

    Header *prev_block = (Header *)ptr_sub(predecessor, sizeof(Header));

    if(predecessor != free_list_head && are_adjacent(prev_block, recovered_header)) {
        //if we coalesce here, then the free_list pointer needs to be updated in case we can coalesce again.
        recovered_header = coalesce(prev_block, recovered_header, NODE2_NOT_IN_LIST);
        free_pointer = ptr_add(recovered_header, sizeof(Header));
    }
    else {
        //set up the free list connections for the preceding node
        free_pointer->next = predecessor->next;
        free_pointer->prev = predecessor;
        predecessor->next = free_pointer;
        free_pointer->next->prev = free_pointer;
    }

    free_list *successor = free_pointer->next;
    if(successor != free_list_head) {
        Header *next_block = (Header *)(ptr_sub(successor, sizeof(Header)));
        next_block->PREV_STATUS = BLOCK_FREE;
        //this is a bit naughty, but since there's no reason to update the free_pointer anymore we can ignore the return value.
        if(are_adjacent(recovered_header, next_block))
            coalesce(recovered_header, next_block, BOTH_IN_LIST);
    }

    return;
}
