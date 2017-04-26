#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/gracl.h>
#include <linux/grsecurity.h>

static struct gr_alloc_state __current_alloc_state = { 1, 1, NULL };
struct gr_alloc_state *current_alloc_state = &__current_alloc_state;

static int
alloc_pop(void)
{
	if (current_alloc_state->alloc_stack_next == 1)
		return 0;

	kfree(current_alloc_state->alloc_stack[current_alloc_state->alloc_stack_next - 2]);

	current_alloc_state->alloc_stack_next--;

	return 1;
}

static int
alloc_push(void *buf)
{
	if (current_alloc_state->alloc_stack_next >= current_alloc_state->alloc_stack_size)
		return 1;

	current_alloc_state->alloc_stack[current_alloc_state->alloc_stack_next - 1] = buf;

	current_alloc_state->alloc_stack_next++;

	return 0;
}

void *
acl_alloc(unsigned long len)
{
	void *ret = NULL;

	if (!len || len > PAGE_SIZE)
		goto out;

	ret = kmalloc(len, GFP_KERNEL);

	if (ret) {
		if (alloc_push(ret)) {
			kfree(ret);
			ret = NULL;
		}
	}

out:
	return ret;
}

void *
acl_alloc_num(unsigned long num, unsigned long len)
{
	if (!len || (num > (PAGE_SIZE / len)))
		return NULL;

	return acl_alloc(num * len);
}

void
acl_free_all(void)
{
	if (!current_alloc_state->alloc_stack)
		return;

	while (alloc_pop()) ;

	if (current_alloc_state->alloc_stack) {
		if ((current_alloc_state->alloc_stack_size * sizeof (void *)) <= PAGE_SIZE)
			kfree(current_alloc_state->alloc_stack);
		else
			vfree(current_alloc_state->alloc_stack);
	}

	current_alloc_state->alloc_stack = NULL;
	current_alloc_state->alloc_stack_size = 1;
	current_alloc_state->alloc_stack_next = 1;

	return;
}

int
acl_alloc_stack_init(unsigned long size)
{
	if ((size * sizeof (void *)) <= PAGE_SIZE)
		current_alloc_state->alloc_stack =
		    (void **) kmalloc(size * sizeof (void *), GFP_KERNEL);
	else
		current_alloc_state->alloc_stack = (void **) vmalloc(size * sizeof (void *));

	current_alloc_state->alloc_stack_size = size;
	current_alloc_state->alloc_stack_next = 1;

	if (!current_alloc_state->alloc_stack)
		return 0;
	else
		return 1;
}
