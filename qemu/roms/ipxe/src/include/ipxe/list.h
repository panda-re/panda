#ifndef _IPXE_LIST_H
#define _IPXE_LIST_H

/** @file
 *
 * Linked lists
 *
 * This linked list handling code is based on the Linux kernel's
 * list.h.
 */

FILE_LICENCE ( GPL2_ONLY );

#include <stddef.h>
#include <assert.h>

/** A doubly-linked list entry (or list head) */
struct list_head {
	/** Next list entry */
	struct list_head *next;
	/** Previous list entry */
	struct list_head *prev;
};

/**
 * Initialise a static list head
 *
 * @v list		List head
 */
#define LIST_HEAD_INIT( list ) { &(list), &(list) }

/**
 * Declare a static list head
 *
 * @v list		List head
 */
#define LIST_HEAD( list ) \
	struct list_head list = LIST_HEAD_INIT ( list )

/**
 * Initialise a list head
 *
 * @v list		List head
 */
#define INIT_LIST_HEAD( list ) do {			\
	(list)->next = (list);				\
	(list)->prev = (list);				\
	} while ( 0 )

/**
 * Check a list entry or list head is valid
 *
 * @v list		List entry or head
 */
#define list_check( list ) ( {				\
	assert ( (list) != NULL );			\
	assert ( (list)->prev != NULL );		\
	assert ( (list)->next != NULL );		\
	assert ( (list)->next->prev == (list) );	\
	assert ( (list)->prev->next == (list) );	\
	} )

/**
 * Insert a list entry between two known consecutive entries
 *
 * @v new		New list entry
 * @v prev		Previous list entry
 * @v next		Next list entry
 */
static inline void __list_add ( struct list_head *new,
				struct list_head *prev,
				struct list_head *next ) {
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

/**
 * Add a new entry to the head of a list
 *
 * @v new		New entry to be added
 * @v head		List head, or entry after which to add the new entry
 */
static inline void list_add ( struct list_head *new, struct list_head *head ) {
	__list_add ( new, head, head->next );
}
#define list_add( new, head ) do {			\
	list_check ( (head) );				\
	list_add ( (new), (head) );			\
	} while ( 0 )

/**
 * Add a new entry to the tail of a list
 *
 * @v new		New entry to be added
 * @v head		List head, or entry before which to add the new entry
 */
static inline void list_add_tail ( struct list_head *new,
				   struct list_head *head ) {
	__list_add ( new, head->prev, head );
}
#define list_add_tail( new, head ) do {			\
	list_check ( (head) );				\
	list_add_tail ( (new), (head) );		\
	} while ( 0 )

/**
 * Delete a list entry between two known consecutive entries
 *
 * @v prev		Previous list entry
 * @v next		Next list entry
 */
static inline void __list_del ( struct list_head *prev,
				struct list_head *next ) {
	next->prev = prev;
	prev->next = next;
}

/**
 * Delete an entry from a list
 *
 * @v list		List entry
 *
 * Note that list_empty() on entry does not return true after this;
 * the entry is in an undefined state.
 */
static inline void list_del ( struct list_head *list ) {
	__list_del ( list->prev, list->next );
}
#define list_del( list ) do {				\
	list_check ( (list) );				\
	list_del ( (list) );				\
	} while ( 0 )

/**
 * Test whether a list is empty
 *
 * @v list		List head
 */
static inline int list_empty ( const struct list_head *list ) {
	return ( list->next == list );
}
#define list_empty( list ) ( {				\
	list_check ( (list) );				\
	list_empty ( (list) ); } )

/**
 * Get the container of a list entry
 *
 * @v list		List entry
 * @v type		Containing type
 * @v member		Name of list field within containing type
 * @ret container	Containing object
 */
#define list_entry( list, type, member ) ( {		\
	list_check ( (list) );				\
	container_of ( list, type, member ); } )

/**
 * Get the container of the first entry in a list
 *
 * @v list		List head
 * @v type		Containing type
 * @v member		Name of list field within containing type
 * @ret first		First list entry, or NULL
 */
#define list_first_entry( list, type, member )		\
	( list_empty ( (list) ) ?			\
	  ( type * ) NULL :				\
	  list_entry ( (list)->next, type, member ) )

/**
 * Iterate over entries in a list
 *
 * @v pos		Iterator
 * @v head		List head
 * @v member		Name of list field within iterator's type
 */
#define list_for_each_entry( pos, head, member )			      \
	for ( list_check ( (head) ),					      \
	      pos = list_entry ( (head)->next, typeof ( *pos ), member );     \
	      &pos->member != (head);					      \
	      pos = list_entry ( pos->member.next, typeof ( *pos ), member ) )

/**
 * Iterate over entries in a list in reverse order
 *
 * @v pos		Iterator
 * @v head		List head
 * @v member		Name of list field within iterator's type
 */
#define list_for_each_entry_reverse( pos, head, member )		      \
	for ( list_check ( (head) ),					      \
	      pos = list_entry ( (head)->prev, typeof ( *pos ), member );     \
	      &pos->member != (head);					      \
	      pos = list_entry ( pos->member.prev, typeof ( *pos ), member ) )

/**
 * Iterate over entries in a list, safe against deletion of the current entry
 *
 * @v pos		Iterator
 * @v tmp		Temporary value (of same type as iterator)
 * @v head		List head
 * @v member		Name of list field within iterator's type
 */
#define list_for_each_entry_safe( pos, tmp, head, member )		      \
	for ( list_check ( (head) ),					      \
	      pos = list_entry ( (head)->next, typeof ( *pos ), member ),     \
	      tmp = list_entry ( pos->member.next, typeof ( *tmp ), member ); \
	      &pos->member != (head);					      \
	      pos = tmp,						      \
	      tmp = list_entry ( tmp->member.next, typeof ( *tmp ), member ) )

#endif /* _IPXE_LIST_H */
