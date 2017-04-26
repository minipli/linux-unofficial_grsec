#ifndef ___ASM_SPARC_PGTABLE_H
#define ___ASM_SPARC_PGTABLE_H
#if defined(__sparc__) && defined(__arch64__)
#include <asm/pgtable_64.h>
#else
#include <asm/pgtable_32.h>
#endif

#define ktla_ktva(addr)		(addr)
#define ktva_ktla(addr)		(addr)

#endif
