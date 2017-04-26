/* 
 * User address space access functions.
 *
 * Copyright 1997 Andi Kleen <ak@muc.de>
 * Copyright 1997 Linus Torvalds
 * Copyright 2002 Andi Kleen <ak@suse.de>
 */
#include <linux/export.h>
#include <linux/uaccess.h>

/*
 * Zero Userspace
 */

unsigned long __clear_user(void __user *addr, unsigned long size)
{
	long __d0;
	might_fault();
	/* no memory constraint because it doesn't change any memory gcc knows
	   about */
	user_access_begin();
	asm volatile(
		"	testq  %[size8],%[size8]\n"
		"	jz     4f\n"
		"0:	movq %[zero],(%[dst])\n"
		"	addq   %[eight],%[dst]\n"
		"	decl %%ecx ; jnz   0b\n"
		"4:	movq  %[size1],%%rcx\n"
		"	testl %%ecx,%%ecx\n"
		"	jz     2f\n"
		"1:	movb   %b[zero],(%[dst])\n"
		"	incq   %[dst]\n"
		"	decl %%ecx ; jnz  1b\n"
		"2:\n"
		".section .fixup,\"ax\"\n"
		"3:	lea 0(%[size1],%[size8],8),%[size8]\n"
		"	jmp 2b\n"
		".previous\n"
		_ASM_EXTABLE(0b,3b)
		_ASM_EXTABLE(1b,2b)
		: [size8] "=&c"(size), [dst] "=&D" (__d0)
		: [size1] "r"(size & 7), "[size8]" (size / 8), "[dst]"(____m(addr)),
		  [zero] "r" (0UL), [eight] "r" (8UL));
	user_access_end();
	return size;
}
EXPORT_SYMBOL(__clear_user);

unsigned long clear_user(void __user *to, unsigned long n)
{
	if (access_ok(VERIFY_WRITE, to, n))
		return __clear_user(to, n);
	return n;
}
EXPORT_SYMBOL(clear_user);

unsigned long copy_in_user(void __user *to, const void __user *from, unsigned long len)
{
	if (access_ok(VERIFY_WRITE, to, len) && access_ok(VERIFY_READ, from, len))
		return copy_user_generic((void __force_kernel *)____m(to), (void __force_kernel *)____m(from), len);
	return len;
}
EXPORT_SYMBOL(copy_in_user);

/*
 * Try to copy last bytes and clear the rest if needed.
 * Since protection fault in copy_from/to_user is not a normal situation,
 * it is not necessary to optimize tail handling.
 */
__visible unsigned long
copy_user_handle_tail(void __user *to, const void __user *from, unsigned long len)
{
	user_access_end();
	for (; len; --len, to++) {
		char c;

		if (__get_user_nocheck(c, (const char *)from++, sizeof(char)))
			break;
		if (__put_user_nocheck(c, (char *)to, sizeof(char)))
			break;
	}

	/* If the destination is a kernel buffer, we always clear the end */
	if (!__addr_ok(to) && (unsigned long)to >= TASK_SIZE_MAX + pax_user_shadow_base)
		memset((void __force_kernel *)to, 0, len);
	return len;
}
