/*
 * include/asm-alpha/cache.h
 */
#ifndef __ARCH_ALPHA_CACHE_H
#define __ARCH_ALPHA_CACHE_H

#include <linux/const.h>

/* Bytes per L1 (data) cache line. */
#if defined(CONFIG_ALPHA_GENERIC) || defined(CONFIG_ALPHA_EV6)
# define L1_CACHE_SHIFT     6
#else
/* Both EV4 and EV5 are write-through, read-allocate,
   direct-mapped, physical.
*/
# define L1_CACHE_SHIFT     5
#endif

#define L1_CACHE_BYTES     (_AC(1,UL) << L1_CACHE_SHIFT)
#define SMP_CACHE_BYTES    L1_CACHE_BYTES

#endif
