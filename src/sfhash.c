#include <sfhash.h>
#include <libntoh.h>

#define sfhash_get16bits(d) (*((const unsigned short *) (d)))

/* The most generic version, hashes an arbitrary sequence
 * of bytes.  No alignment or length assumptions are made about
 * the input key.
 */
_HIDDEN unsigned int sfhash(const void * key, unsigned int len, unsigned int initval)
{
	const char	*data = key;
	unsigned int	hash = len + initval, tmp;
	int		rem;

	if (len <= 0 || !data )
		return 0;

	rem = len & 3;
	len >>= 2;

	/* Main loop */
	for (; len > 0; len--)
	{
		/* Mix 32bit chunk of the data */
		hash += sfhash_get16bits(data);
		tmp   = (sfhash_get16bits(data+2) << 11) ^ hash;
		hash  = (hash << 16) ^ tmp;
		data += 2*sizeof(unsigned short);
		hash += hash >> 11;
	}

	/* Handle end cases */
	switch (rem)
	{
		case 3:	hash += *((unsigned short *)data);
			hash ^= hash << 16;
			hash ^= data[sizeof(unsigned short)] << 18;
			hash += hash >> 11;
			break;

		case 2:	hash += *((unsigned short *)data);
			hash ^= hash << 11;
			hash += hash >> 17;
			break;

		case 1: hash += *data;
			hash ^= hash << 10;
			hash += hash >> 1;
			break;
	}

	/* Force "avalanching" of final 127 bits */
	hash ^= hash << 3;
	hash += hash >> 5;
	hash ^= hash << 2;
	hash += hash >> 15;
	hash ^= hash << 10;

	return hash;
}
