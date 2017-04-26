/* Rewritten and vastly simplified by Rusty Russell for in-kernel
 * module loader:
 *   Copyright 2002 Rusty Russell <rusty@rustcorp.com.au> IBM Corporation
 */
#ifndef _LINUX_KALLSYMS_H
#define _LINUX_KALLSYMS_H

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/stddef.h>

#define KSYM_NAME_LEN 128
#define KSYM_SYMBOL_LEN (sizeof("%s+%#lx/%#lx [%s]") + (KSYM_NAME_LEN - 1) + \
			 2*(BITS_PER_LONG*3/10) + (MODULE_NAME_LEN - 1) + 1)

struct module;

#if !defined(__INCLUDED_BY_HIDESYM) || !defined(CONFIG_KALLSYMS)
#if defined(CONFIG_KALLSYMS) && !defined(CONFIG_GRKERNSEC_HIDESYM)
/* Lookup the address for a symbol. Returns 0 if not found. */
unsigned long kallsyms_lookup_name(const char *name);

/* Call a function on each kallsyms symbol in the core kernel */
int kallsyms_on_each_symbol(int (*fn)(void *, const char *, struct module *,
				      unsigned long),
			    void *data);

extern int kallsyms_lookup_size_offset(unsigned long addr,
				  unsigned long *symbolsize,
				  unsigned long *offset);

/* Lookup an address.  modname is set to NULL if it's in the kernel. */
const char *kallsyms_lookup(unsigned long addr,
			    unsigned long *symbolsize,
			    unsigned long *offset,
			    char **modname, char *namebuf);

/* Look up a kernel symbol and return it in a text buffer. */
extern int sprint_symbol(char *buffer, unsigned long address);
extern int sprint_symbol_no_offset(char *buffer, unsigned long address);
extern int sprint_backtrace(char *buffer, unsigned long address);

/* Look up a kernel symbol and print it to the kernel messages. */
extern __printf(1, 3) void __print_symbol(const char *fmt, unsigned long address, ...);

int lookup_symbol_name(unsigned long addr, char *symname);
int lookup_symbol_attrs(unsigned long addr, unsigned long *size, unsigned long *offset, char *modname, char *name);

#else /* !CONFIG_KALLSYMS */

static inline unsigned long kallsyms_lookup_name(const char *name)
{
	return 0;
}

static inline int kallsyms_on_each_symbol(int (*fn)(void *, const char *,
						    struct module *,
						    unsigned long),
					  void *data)
{
	return 0;
}

static inline int kallsyms_lookup_size_offset(unsigned long addr,
					      unsigned long *symbolsize,
					      unsigned long *offset)
{
	return 0;
}

static inline const char *kallsyms_lookup(unsigned long addr,
					  unsigned long *symbolsize,
					  unsigned long *offset,
					  char **modname, char *namebuf)
{
	return NULL;
}

static inline int sprint_symbol(char *buffer, unsigned long addr)
{
	*buffer = '\0';
	return 0;
}

static inline int sprint_symbol_no_offset(char *buffer, unsigned long addr)
{
	*buffer = '\0';
	return 0;
}

static inline int sprint_backtrace(char *buffer, unsigned long addr)
{
	*buffer = '\0';
	return 0;
}

static inline int lookup_symbol_name(unsigned long addr, char *symname)
{
	return -ERANGE;
}

static inline int lookup_symbol_attrs(unsigned long addr, unsigned long *size, unsigned long *offset, char *modname, char *name)
{
	return -ERANGE;
}

/* Stupid that this does nothing, but I didn't create this mess. */
#define __print_symbol(fmt, addr, args...)
#endif /*CONFIG_KALLSYMS*/
#else /* when included by kallsyms.c, vsnprintf.c, kprobes.c, or
	arch/x86/kernel/dumpstack.c, with HIDESYM enabled */
extern unsigned long kallsyms_lookup_name(const char *name);
extern __printf(1, 3) void __print_symbol(const char *fmt, unsigned long address, ...);
extern int sprint_backtrace(char *buffer, unsigned long address);
extern int sprint_symbol(char *buffer, unsigned long address);
extern int sprint_symbol_no_offset(char *buffer, unsigned long address);
const char *kallsyms_lookup(unsigned long addr,
			    unsigned long *symbolsize,
			    unsigned long *offset,
			    char **modname, char *namebuf);
extern int kallsyms_lookup_size_offset(unsigned long addr,
				  unsigned long *symbolsize,
				  unsigned long *offset);
#endif

#define print_symbol(fmt, addr) \
	__print_symbol(fmt, addr, "")

static inline void print_ip_sym(unsigned long ip)
{
	printk("[<%p>] %pS\n", (void *) ip, (void *) ip);
}

#endif /*_LINUX_KALLSYMS_H*/
