#ifndef __ASM_AVR32_KMAP_TYPES_H
#define __ASM_AVR32_KMAP_TYPES_H

#ifdef CONFIG_DEBUG_HIGHMEM
# define KM_TYPE_NR 30
#else
# define KM_TYPE_NR 15
#endif

#endif /* __ASM_AVR32_KMAP_TYPES_H */
