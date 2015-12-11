#ifndef __LIBNTOH_COMMON_H__
# define __LIBNTOH_COMMON_H__

/********************************************************************************
 * Copyright (c) 2012, Chema Garcia                                             *
 * All rights reserved.                                                         *
 *                                                                              *
 * Redistribution and use in source and binary forms, with or                   *
 * without modification, are permitted provided that the following              *
 * conditions are met:                                                          *
 *                                                                              *
 *    * Redistributions of source code must retain the above                    *
 *      copyright notice, this list of conditions and the following             *
 *      disclaimer.                                                             *
 *                                                                              *
 *    * Redistributions in binary form must reproduce the above                 *
 *      copyright notice, this list of conditions and the following             *
 *      disclaimer in the documentation and/or other materials provided         *
 *      with the distribution.                                                  *
 *                                                                              *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"  *
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE    *
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE   *
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE    *
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR          *
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF         *
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS     *
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN      *
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)      *
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE   *
 * POSSIBILITY OF SUCH DAMAGE.                                                  *
 ********************************************************************************/

#ifndef _HIDDEN
# define _HIDDEN __attribute__((visibility("hidden")))
#endif

/* linked list */
typedef struct _hash_node_
{
	struct _hash_node_	*next;
	void			*val;
	unsigned int		key;
} htnode_t , *phtnode_t;

/* hash table definition */
typedef struct
{
	size_t		table_size;
	phtnode_t	*table;
} htable_t , *phtable_t;

/******************************************************************/
/** Hash Table implementation (collision resolution by chaining) **/
/******************************************************************/
phtable_t htable_map ( size_t size );
int htable_insert ( phtable_t ht  , unsigned int key , void *val );
void *htable_find ( phtable_t ht , unsigned int key, void *ip_tuple4 );
void *htable_remove ( phtable_t ht , unsigned int key, void *ip_tuple4 );
unsigned int htable_count ( phtable_t ht );
unsigned int htable_first ( phtable_t ht );
void htable_destroy ( phtable_t *ht );


/** @brief Access locking **/
void lock_access ( pntoh_lock_t lock );
/** @brief Access unlocking **/
void unlock_access ( pntoh_lock_t lock );
void free_lockaccess ( pntoh_lock_t lock );

#endif /* __LIBNTOH_COMMON_H__ */
