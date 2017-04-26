#ifndef __ASM_LIBGCC_H
#define __ASM_LIBGCC_H

#include <asm/byteorder.h>

typedef int word_type __attribute__ ((mode (__word__)));

#ifdef CONFIG_64BIT
typedef int DWtype __attribute__((mode(TI)));
#else
typedef long long DWtype;
#endif

#ifdef __BIG_ENDIAN
struct DWstruct {
	long high, low;
};
#elif defined(__LITTLE_ENDIAN)
struct DWstruct {
	long low, high;
};
#else
#error I feel sick.
#endif

typedef union {
	struct DWstruct s;
	DWtype ll;
} DWunion;

#endif /* __ASM_LIBGCC_H */
