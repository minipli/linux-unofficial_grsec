/*
 * Copyright 2006, Red Hat, Inc., Dave Jones
 * Released under the General Public License (GPL).
 *
 * This file contains the linked list implementations for
 * DEBUG_LIST.
 */

#include <linux/export.h>
#include <linux/list.h>
#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/rculist.h>
#include <linux/mm.h>

#ifdef CONFIG_DEBUG_LIST
/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */

static bool __list_add_debug(struct list_head *new,
			     struct list_head *prev,
			     struct list_head *next)
{
	if (unlikely(next->prev != prev)) {
		printk(KERN_ERR "list_add corruption. next->prev should be "
			"prev (%p), but was %p. (next=%p).\n",
			prev, next->prev, next);
		BUG();
		return false;
	}
	if (unlikely(prev->next != next)) {
		printk(KERN_ERR "list_add corruption. prev->next should be "
			"next (%p), but was %p. (prev=%p).\n",
			next, prev->next, prev);
		BUG();
		return false;
	}
	if (unlikely(new == prev || new == next)) {
		printk(KERN_ERR "list_add double add: new=%p, prev=%p, next=%p.\n",
			new, prev, next);
		BUG();
		return false;
	}
	return true;
}

void __list_add(struct list_head *new,
		struct list_head *prev,
		struct list_head *next)
{
	if (!__list_add_debug(new, prev, next))
		return;

	next->prev = new;
	new->next = next;
	new->prev = prev;
	WRITE_ONCE(prev->next, new);
}
EXPORT_SYMBOL(__list_add);

static bool __list_del_entry_debug(struct list_head *entry)
{
	struct list_head *prev, *next;

	prev = entry->prev;
	next = entry->next;

	if (unlikely(next == LIST_POISON1)) {
		printk(KERN_ERR "list_del corruption, %p->next is LIST_POISON1 (%p)\n",
			entry, LIST_POISON1);
		BUG();
		return false;
	}
	if (unlikely(prev == LIST_POISON2)) {
		printk(KERN_ERR "list_del corruption, %p->prev is LIST_POISON2 (%p)\n",
			entry, LIST_POISON2);
		BUG();
		return false;
	}
	if (unlikely(entry->prev->next != entry)) {
		printk(KERN_ERR "list_del corruption. prev->next should be %p, "
			"but was %p\n", entry, prev->next);
		BUG();
		return false;
	}
	if (unlikely(entry->next->prev != entry)) {
		printk(KERN_ERR "list_del corruption. next->prev should be %p, "
			"but was %p\n", entry, next->prev);
		BUG();
		return false;
	}
	return true;
}

void __list_del_entry(struct list_head *entry)
{
	if (!__list_del_entry_debug(entry))
		return;

	__list_del(entry->prev, entry->next);
}
EXPORT_SYMBOL(__list_del_entry);

/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty on entry does not return true after this, the entry is
 * in an undefined state.
 */
void list_del(struct list_head *entry)
{
	__list_del_entry(entry);
	entry->next = LIST_POISON1;
	entry->prev = LIST_POISON2;
}
EXPORT_SYMBOL(list_del);

/*
 * RCU variants.
 */
void __list_add_rcu(struct list_head *new,
		    struct list_head *prev, struct list_head *next)
{
	if (!__list_add_debug(new, prev, next))
		return;

	new->next = next;
	new->prev = prev;
	rcu_assign_pointer(list_next_rcu(prev), new);
	next->prev = new;
}
EXPORT_SYMBOL(__list_add_rcu);
#endif

void __pax_list_add(struct list_head *new, struct list_head *prev, struct list_head *next)
{
#ifdef CONFIG_DEBUG_LIST
	if (!__list_add_debug(new, prev, next))
		return;
#endif

	pax_open_kernel();
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
	pax_close_kernel();
}
EXPORT_SYMBOL(__pax_list_add);

void pax_list_del(struct list_head *entry)
{
#ifdef CONFIG_DEBUG_LIST
	if (!__list_del_entry_debug(entry))
		return;
#endif

	pax_open_kernel();
	__list_del(entry->prev, entry->next);
	entry->next = LIST_POISON1;
	entry->prev = LIST_POISON2;
	pax_close_kernel();
}
EXPORT_SYMBOL(pax_list_del);

void pax_list_del_init(struct list_head *entry)
{
	pax_open_kernel();
	__list_del(entry->prev, entry->next);
	INIT_LIST_HEAD(entry);
	pax_close_kernel();
}
EXPORT_SYMBOL(pax_list_del_init);

void __pax_list_add_rcu(struct list_head *new,
			struct list_head *prev, struct list_head *next)
{
#ifdef CONFIG_DEBUG_LIST
	if (!__list_add_debug(new, prev, next))
		return;
#endif

	pax_open_kernel();
	new->next = next;
	new->prev = prev;
	rcu_assign_pointer(list_next_rcu(prev), new);
	next->prev = new;
	pax_close_kernel();
}
EXPORT_SYMBOL(__pax_list_add_rcu);

void pax_list_del_rcu(struct list_head *entry)
{
#ifdef CONFIG_DEBUG_LIST
	if (!__list_del_entry_debug(entry))
		return;
#endif

	pax_open_kernel();
	__list_del(entry->prev, entry->next);
	entry->prev = LIST_POISON2;
	pax_close_kernel();
}
EXPORT_SYMBOL(pax_list_del_rcu);
