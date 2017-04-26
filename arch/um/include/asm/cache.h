#ifndef __UM_CACHE_H
#define __UM_CACHE_H

#include <linux/const.h>

#if defined(CONFIG_UML_X86) && !defined(CONFIG_64BIT)
# define L1_CACHE_SHIFT		(CONFIG_X86_L1_CACHE_SHIFT)
#elif defined(CONFIG_UML_X86) /* 64-bit */
# define L1_CACHE_SHIFT		6 /* Should be 7 on Intel */
#else
/* XXX: this was taken from x86, now it's completely random. Luckily only
 * affects SMP padding. */
# define L1_CACHE_SHIFT		5
#endif

#define L1_CACHE_BYTES		(_AC(1,UL) << L1_CACHE_SHIFT)

#endif
