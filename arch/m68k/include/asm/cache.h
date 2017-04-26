/*
 * include/asm-m68k/cache.h
 */
#ifndef __ARCH_M68K_CACHE_H
#define __ARCH_M68K_CACHE_H

#include <linux/const.h>

/* bytes per L1 cache line */
#define        L1_CACHE_SHIFT  4
#define        L1_CACHE_BYTES  (_AC(1,UL) << L1_CACHE_SHIFT)

#define ARCH_DMA_MINALIGN	L1_CACHE_BYTES

#endif
