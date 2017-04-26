#ifndef _ASM_ARCH_CACHE_H
#define _ASM_ARCH_CACHE_H

#include <linux/const.h>
/* Etrax 100LX have 32-byte cache-lines. */
#define L1_CACHE_SHIFT 5
#define L1_CACHE_BYTES (_AC(1,UL) << L1_CACHE_SHIFT)

#endif /* _ASM_ARCH_CACHE_H */
