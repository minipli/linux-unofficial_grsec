#ifndef _X86_MMAN_H
#define _X86_MMAN_H

#include <uapi/asm/mman.h>

#ifdef __KERNEL__
#ifndef __ASSEMBLY__
#ifdef CONFIG_X86_32
#define arch_mmap_check	i386_mmap_check
int i386_mmap_check(unsigned long addr, unsigned long len, unsigned long flags);
#endif
#endif
#endif

#endif /* X86_MMAN_H */
