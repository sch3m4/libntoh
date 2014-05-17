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

#include <stdlib.h>
#include <libntoh.h>
#include <ipv4defrag.h>

// Uniqueness test for IP fragments, using their tuples
// @contrib: Eosis - https://github.com/Eosis
inline int ip_tuple4_equals_to(ntoh_ipv4_tuple4_t* x, ntoh_ipv4_tuple4_t* y)
{
    if (x->source != y->source)
      return 0;

    if (x->destination != y->destination)
      return 0;

    if (x->protocol != y->protocol)
      return 0;

    if (x->id != y->id)
      return 0;

    return 1;
}

/****************/
/** HASH TABLE **/
/****************/
/* map the hash table */
_HIDDEN phtable_t htable_map ( size_t size )
{
	phtable_t ret = 0;

	if ( !size )
		return 0;

	ret = (phtable_t) calloc ( 1 , sizeof ( htable_t ) );
	ret->table = (phtnode_t*) calloc ( size , sizeof ( phtnode_t ) );
	ret->table_size = size;

	return ret;
}

/* insert a pair key-value into the hash table */
_HIDDEN int htable_insert ( phtable_t ht  , unsigned int key , void *val )
{
	phtnode_t node = 0;
	phtnode_t aux = 0;
	unsigned int index = 0;

	if ( !ht || !val )
		return 0;

	node = (phtnode_t) calloc ( 1 , sizeof ( htnode_t ) );
	node->key = key;
	node->val = val;

	index = key % ht->table_size;

	if ( ht->table[index] == NULL )
	{
		ht->table[index] = node;
		return 1;
	}

	/* collision resolution by chaining */
	aux = ht->table[index];
	while ( aux->next != 0 )
		aux = aux->next;

	aux->next = node;

	return 1;
}

/* returns the value associated to the given key */
_HIDDEN void *htable_find ( phtable_t ht , unsigned int key, void* ip_tuple4 )
{
	unsigned int index = 0;
	phtnode_t node = 0;

	if ( !ht )
		return 0;

	index = key % ht->table_size;

	node = ht->table[index];

	// @contrib: Eosis - https://github.com/Eosis
	if ( ip_tuple4 != 0 ) //if not null
		while( node != 0 && !(ip_tuple4_equals_to((ntoh_ipv4_tuple4_t*)ip_tuple4, &(((pntoh_ipv4_flow_t)(node->val))->ident))) )
			node = node->next;
	else
		while ( node != 0 && node->key != key )
			node = node->next;

	if ( !node )
		return 0;

	return node->val;
}

/* removes a key-value pair from the hash table */
_HIDDEN void *htable_remove ( phtable_t ht , unsigned int key, void* ip_tuple4 )
{
	unsigned int index = 0;
	phtnode_t node = 0;
	phtnode_t aux = 0;
	void *ret = 0;

	if ( !ht )
		return 0;

	index = key % ht->table_size;
	node = ht->table[index];

	if ( node->key == key )
		ht->table[index] = node->next;
	else
	{
		while ( node->next != 0 && node->next->key != key )
			node = node->next;

		// @contrib: Eosis - https://github.com/Eosis
		if (ip_tuple4) //if not null
			while( node->next != 0 && !(ip_tuple4_equals_to((pntoh_ipv4_tuple4_t)ip_tuple4, &(((pntoh_ipv4_flow_t)(node->next->val))->ident))) )
				node = node->next;
		else
			while ( node->next != 0 && node->next->key != key )
				node = node->next;

		if ( node->next != 0 )
		{
			aux = node;
			node = node->next;
			aux->next = node->next;
		}
	}

	if ( !node )
		return 0;

	ret = node->val;
	free ( node );

	return ret;
}

/* count the key-value pairs in a hash table */
_HIDDEN unsigned int htable_count ( phtable_t ht )
{
	unsigned int i = 0;
	unsigned int ret = 0;
	phtnode_t aux = 0;

	if ( !ht )
		return ret;

	for ( i = 0 ; i < ht->table_size ; i++ )
		for ( aux = ht->table[i] ; aux != 0 ; ret++ , aux = aux->next );

	return ret;
}

/* gets the first key in a hash table */
_HIDDEN unsigned int htable_first ( phtable_t ht )
{
	unsigned int ret = 0;
	unsigned int i = 0;

	if ( ! ht )
		return ret;

	for ( i = 0 ; i < ht->table_size && ht->table[i] == 0 ; i++ );

	if ( i < ht->table_size )
		ret = ht->table[i]->key;

	return ret;
}

/* destroys entire hash table */
_HIDDEN void htable_destroy ( phtable_t *ht )
{
	unsigned int i = 0;
	phtnode_t aux = 0;

	if ( !ht || !(*ht) )
		return;

	for ( i = 0 ; i < (*ht)->table_size ; i++ )
		while ( (*ht)->table[i] != 0 )
		{
			aux = (*ht)->table[i]->next;
			free ( (*ht)->table[i] );
			(*ht)->table[i] = aux;
		}

	free ( (*ht)->table );
	free ( *ht );

	*ht = 0;

	return;
}

/********************/
/** ACCESS LOCKING **/
/********************/
_HIDDEN void lock_access ( pntoh_lock_t lock )
{
	pthread_mutex_lock( &lock->mutex );

	while ( lock->use )
		pthread_cond_wait( &lock->pcond, &lock->mutex );

	lock->use = 1;

	pthread_mutex_unlock( &lock->mutex );

	return;
}

_HIDDEN void unlock_access ( pntoh_lock_t lock )
{
	pthread_mutex_lock( &lock->mutex );

	lock->use = 0;
	pthread_cond_signal( &lock->pcond );

	pthread_mutex_unlock( &lock->mutex );

	return;
}

_HIDDEN void free_lockaccess ( pntoh_lock_t lock )
{
	pthread_cond_destroy( &lock->pcond );
	pthread_mutex_destroy( &lock->mutex );

	return;
}
