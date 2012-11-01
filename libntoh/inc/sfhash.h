#ifndef _LINUX_SFHASH_H
#define _LINUX_SFHASH_H

/* sfhash.h: SuperFastHash support.
 *
 * Copyright (C) 2004 by Paul Hsieh 
 *
 * http://www.azillionmonkeys.com/qed/hash.html
 *
 */

unsigned int sfhash_3words(unsigned int a, unsigned int b, unsigned int c, unsigned int initval);

#endif