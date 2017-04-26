/*
 * SLOB Allocator: Simple List Of Blocks
 *
 * Matt Mackall <mpm@selenic.com> 12/30/03
 *
 * NUMA support by Paul Mundt, 2007.
 *
 * How SLOB works:
 *
 * The core of SLOB is a traditional K&R style heap allocator, with
 * support for returning aligned objects. The granularity of this
 * allocator is as little as 2 bytes, however typically most architectures
 * will require 4 bytes on 32-bit and 8 bytes on 64-bit.
 *
 * The slob heap is a set of linked list of pages from alloc_pages(),
 * and within each page, there is a singly-linked list of free blocks
 * (slob_t). The heap is grown on demand. To reduce fragmentation,
 * heap pages are segregated into three lists, with objects less than
 * 256 bytes, objects less than 1024 bytes, and all other objects.
 *
 * Allocation from heap involves first searching for a page with
 * sufficient free blocks (using a next-fit-like approach) followed by
 * a first-fit scan of the page. Deallocation inserts objects back
 * into the free list in address order, so this is effectively an
 * address-ordered first fit.
 *
 * Above this is an implementation of kmalloc/kfree. Blocks returned
 * from kmalloc are prepended with a 4-byte header with the kmalloc size.
 * If kmalloc is asked for objects of PAGE_SIZE or larger, it calls
 * alloc_pages() directly, allocating compound pages so the page order
 * does not have to be separately tracked.
 * These objects are detected in kfree() because PageSlab()
 * is false for them.
 *
 * SLAB is emulated on top of SLOB by simply calling constructors and
 * destructors for every SLAB allocation. Objects are returned with the
 * 4-byte alignment unless the SLAB_HWCACHE_ALIGN flag is set, in which
 * case the low-level allocator will fragment blocks to create the proper
 * alignment. Again, objects of page-size or greater are allocated by
 * calling alloc_pages(). As SLAB objects know their size, no separate
 * size bookkeeping is necessary and there is essentially no allocation
 * space overhead, and compound pages aren't needed for multi-page
 * allocations.
 *
 * NUMA support in SLOB is fairly simplistic, pushing most of the real
 * logic down to the page allocator, and simply doing the node accounting
 * on the upper levels. In the event that a node id is explicitly
 * provided, __alloc_pages_node() with the specified node id is used
 * instead. The common case (or when the node id isn't explicitly provided)
 * will default to the current node, as per numa_node_id().
 *
 * Node aware pages are still inserted in to the global freelist, and
 * these are scanned for by matching against the node id encoded in the
 * page flags. As a result, block allocations that can be satisfied from
 * the freelist will only be done so on pages residing on the same node,
 * in order to prevent random node placement.
 */

#include <linux/kernel.h>
#include <linux/slab.h>

#include <linux/mm.h>
#include <linux/swap.h> /* struct reclaim_state */
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <linux/kmemleak.h>
#include <linux/vmalloc.h>

#include <trace/events/kmem.h>

#include <linux/atomic.h>

#include "slab.h"
/*
 * slob_block has a field 'units', which indicates size of block if +ve,
 * or offset of next block if -ve (in SLOB_UNITs).
 *
 * Free blocks of size 1 unit simply contain the offset of the next block.
 * Those with larger size contain their size in the first SLOB_UNIT of
 * memory, and the offset of the next free block in the second SLOB_UNIT.
 */
#if PAGE_SIZE <= (32767 * 2)
typedef s16 slobidx_t;
#else
typedef s32 slobidx_t;
#endif

struct slob_block {
	slobidx_t units;
};
typedef struct slob_block slob_t;

/*
 * All partially free slob pages go on these lists.
 */
#define SLOB_BREAK1 256
#define SLOB_BREAK2 1024
static LIST_HEAD(free_slob_small);
static LIST_HEAD(free_slob_medium);
static LIST_HEAD(free_slob_large);

/*
 * slob_page_free: true for pages on free_slob_pages list.
 */
static inline int slob_page_free(struct page *sp)
{
	return PageSlobFree(sp);
}

static void set_slob_page_free(struct page *sp, struct list_head *list)
{
	list_add(&sp->lru, list);
	__SetPageSlobFree(sp);
}

static inline void clear_slob_page_free(struct page *sp)
{
	list_del(&sp->lru);
	__ClearPageSlobFree(sp);
}

#define SLOB_UNIT sizeof(slob_t)
#define SLOB_UNITS(size) DIV_ROUND_UP(size, SLOB_UNIT)

/*
 * struct slob_rcu is inserted at the tail of allocated slob blocks, which
 * were created with a SLAB_DESTROY_BY_RCU slab. slob_rcu is used to free
 * the block using call_rcu.
 */
struct slob_rcu {
	struct rcu_head head;
	int size;
};

/*
 * slob_lock protects all slob allocator structures.
 */
static DEFINE_SPINLOCK(slob_lock);

/*
 * Encode the given size and next info into a free slob block s.
 */
static void set_slob(slob_t *s, slobidx_t size, slob_t *next)
{
	slob_t *base = (slob_t *)((unsigned long)s & PAGE_MASK);
	slobidx_t offset = next - base;

	if (size > 1) {
		s[0].units = size;
		s[1].units = offset;
	} else
		s[0].units = -offset;
}

/*
 * Return the size of a slob block.
 */
static slobidx_t slob_units(const slob_t *s)
{
	if (s->units > 0)
		return s->units;
	return 1;
}

/*
 * Return the next free slob block pointer after this one.
 */
static slob_t *slob_next(const slob_t *s)
{
	slob_t *base = (slob_t *)((unsigned long)s & PAGE_MASK);
	slobidx_t next;

	if (s[0].units < 0)
		next = -s[0].units;
	else
		next = s[1].units;
	return base+next;
}

/*
 * Returns true if s is the last free block in its page.
 */
static int slob_last(const slob_t *s)
{
	return !((unsigned long)slob_next(s) & ~PAGE_MASK);
}

static struct page *slob_new_pages(gfp_t gfp, unsigned int order, int node)
{
	struct page *page;

#ifdef CONFIG_NUMA
	if (node != NUMA_NO_NODE)
		page = __alloc_pages_node(node, gfp, order);
	else
#endif
		page = alloc_pages(gfp, order);

	if (!page)
		return NULL;

	__SetPageSlab(page);
	return page;
}

static void slob_free_pages(struct page *sp, int order)
{
	if (current->reclaim_state)
		current->reclaim_state->reclaimed_slab += 1 << order;
	__ClearPageSlab(sp);
	page_mapcount_reset(sp);
	sp->private = 0;
	__free_pages(sp, order);
}

/*
 * Allocate a slob block within a given slob_page sp.
 */
static void *slob_page_alloc(struct page *sp, size_t size, int align)
{
	slob_t *prev, *cur, *aligned = NULL;
	int delta = 0, units = SLOB_UNITS(size);

	for (prev = NULL, cur = sp->freelist; ; prev = cur, cur = slob_next(cur)) {
		slobidx_t avail = slob_units(cur);

		if (align) {
			aligned = (slob_t *)ALIGN((unsigned long)cur, align);
			delta = aligned - cur;
		}
		if (avail >= units + delta) { /* room enough? */
			slob_t *next;

			if (delta) { /* need to fragment head to align? */
				next = slob_next(cur);
				set_slob(aligned, avail - delta, next);
				set_slob(cur, delta, aligned);
				prev = cur;
				cur = aligned;
				avail = slob_units(cur);
			}

			next = slob_next(cur);
			if (avail == units) { /* exact fit? unlink. */
				if (prev)
					set_slob(prev, slob_units(prev), next);
				else
					sp->freelist = next;
			} else { /* fragment */
				if (prev)
					set_slob(prev, slob_units(prev), cur + units);
				else
					sp->freelist = cur + units;
				set_slob(cur + units, avail - units, next);
			}

			sp->units -= units;
			BUG_ON(sp->units < 0);
			if (!sp->units)
				clear_slob_page_free(sp);
			return cur;
		}
		if (slob_last(cur))
			return NULL;
	}
}

/*
 * slob_alloc: entry point into the slob allocator.
 */
static void *slob_alloc(size_t size, gfp_t gfp, int align, int node)
{
	struct page *sp;
	struct list_head *prev;
	struct list_head *slob_list;
	slob_t *b = NULL;
	unsigned long flags;

	if (size < SLOB_BREAK1)
		slob_list = &free_slob_small;
	else if (size < SLOB_BREAK2)
		slob_list = &free_slob_medium;
	else
		slob_list = &free_slob_large;

	spin_lock_irqsave(&slob_lock, flags);
	/* Iterate through each partially free page, try to find room */
	list_for_each_entry(sp, slob_list, lru) {
#ifdef CONFIG_NUMA
		/*
		 * If there's a node specification, search for a partial
		 * page with a matching node id in the freelist.
		 */
		if (node != NUMA_NO_NODE && page_to_nid(sp) != node)
			continue;
#endif
		/* Enough room on this page? */
		if (sp->units < SLOB_UNITS(size))
			continue;

		/* Attempt to alloc */
		prev = sp->lru.prev;
		b = slob_page_alloc(sp, size, align);
		if (!b)
			continue;

		/* Improve fragment distribution and reduce our average
		 * search time by starting our next search here. (see
		 * Knuth vol 1, sec 2.5, pg 449) */
		if (prev != slob_list->prev &&
				slob_list->next != prev->next)
			list_move_tail(slob_list, prev->next);
		break;
	}
	spin_unlock_irqrestore(&slob_lock, flags);

	/* Not enough space: must allocate a new page */
	if (!b) {
		sp = slob_new_pages(gfp & ~__GFP_ZERO, 0, node);
		if (!sp)
			return NULL;
		b = page_address(sp);

		spin_lock_irqsave(&slob_lock, flags);
		sp->units = SLOB_UNITS(PAGE_SIZE);
		sp->freelist = b;
		sp->private = 0;
		INIT_LIST_HEAD(&sp->lru);
		set_slob(b, SLOB_UNITS(PAGE_SIZE), b + SLOB_UNITS(PAGE_SIZE));
		set_slob_page_free(sp, slob_list);
		b = slob_page_alloc(sp, size, align);
		BUG_ON(!b);
		spin_unlock_irqrestore(&slob_lock, flags);
	}
	if (unlikely((gfp & __GFP_ZERO) && b))
		memset(b, 0, size);
	return b;
}

/*
 * slob_free: entry point into the slob allocator.
 */
static void slob_free(struct kmem_cache *c, void *block, int size)
{
	struct page *sp;
	slob_t *prev, *next, *b = (slob_t *)block;
	slobidx_t units;
	unsigned long flags;
	struct list_head *slob_list;

	if (unlikely(ZERO_OR_NULL_PTR(block)))
		return;
	BUG_ON(!size);

	sp = virt_to_head_page(block);
	BUG_ON(virt_to_page(block) != sp);
	units = SLOB_UNITS(size);

	spin_lock_irqsave(&slob_lock, flags);

	if (sp->units + units == SLOB_UNITS(PAGE_SIZE)) {
		/* Go directly to page allocator. Do not pass slob allocator */
		if (slob_page_free(sp))
			clear_slob_page_free(sp);
		spin_unlock_irqrestore(&slob_lock, flags);
		slob_free_pages(sp, 0);
		return;
	}

#ifdef CONFIG_PAX_MEMORY_SANITIZE
	if (pax_sanitize_slab && !(c && (c->flags & SLAB_NO_SANITIZE)))
		memset(block, PAX_MEMORY_SANITIZE_VALUE, size);
#endif

	if (!slob_page_free(sp)) {
		/* This slob page is about to become partially free. Easy! */
		sp->units = units;
		sp->freelist = b;
		set_slob(b, units,
			(void *)((unsigned long)(b +
					SLOB_UNITS(PAGE_SIZE)) & PAGE_MASK));
		if (size < SLOB_BREAK1)
			slob_list = &free_slob_small;
		else if (size < SLOB_BREAK2)
			slob_list = &free_slob_medium;
		else
			slob_list = &free_slob_large;
		set_slob_page_free(sp, slob_list);
		goto out;
	}

	/*
	 * Otherwise the page is already partially free, so find reinsertion
	 * point.
	 */
	sp->units += units;

	if (b < (slob_t *)sp->freelist) {
		if (b + units == sp->freelist) {
			units += slob_units(sp->freelist);
			sp->freelist = slob_next(sp->freelist);
		}
		set_slob(b, units, sp->freelist);
		sp->freelist = b;
	} else {
		prev = sp->freelist;
		next = slob_next(prev);
		while (b > next) {
			prev = next;
			next = slob_next(prev);
		}

		if (!slob_last(prev) && b + units == next) {
			units += slob_units(next);
			set_slob(b, units, slob_next(next));
		} else
			set_slob(b, units, next);

		if (prev + slob_units(prev) == b) {
			units = slob_units(b) + slob_units(prev);
			set_slob(prev, units, slob_next(b));
		} else
			set_slob(prev, slob_units(prev), b);
	}
out:
	spin_unlock_irqrestore(&slob_lock, flags);
}

/*
 * End of slob allocator proper. Begin kmem_cache_alloc and kmalloc frontend.
 */

static __always_inline void *
__do_kmalloc_node_align(size_t size, gfp_t gfp, int node, unsigned long caller, int align)
{
	slob_t *m;
	void *ret = NULL;

	gfp &= gfp_allowed_mask;

	lockdep_trace_alloc(gfp);

	if (size < PAGE_SIZE - align) {
		if (!size)
			return ZERO_SIZE_PTR;

		m = slob_alloc(size + align, gfp, align, node);

		if (!m)
			return NULL;
		BUILD_BUG_ON(ARCH_KMALLOC_MINALIGN < 2 * SLOB_UNIT);
		BUILD_BUG_ON(ARCH_SLAB_MINALIGN < 2 * SLOB_UNIT);
		m[0].units = size;
		m[1].units = align;
		ret = (void *)m + align;

		trace_kmalloc_node(caller, ret,
				   size, size + align, gfp, node);
	} else {
		unsigned int order = get_order(size);
		struct page *page;

		if (likely(order))
			gfp |= __GFP_COMP;
		page = slob_new_pages(gfp, order, node);
		if (page) {
			ret = page_address(page);
			page->private = size;
		}

		trace_kmalloc_node(caller, ret,
				   size, PAGE_SIZE << order, gfp, node);
	}

	return ret;
}

static __always_inline void *
__do_kmalloc_node(size_t size, gfp_t gfp, int node, unsigned long caller)
{
	int align = max(ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MINALIGN);
	void *ret = __do_kmalloc_node_align(size, gfp, node, caller, align);

	if (!ZERO_OR_NULL_PTR(ret))
		kmemleak_alloc(ret, size, 1, gfp);
	return ret;
}

void * __size_overflow(1) __kmalloc(size_t size, gfp_t gfp)
{
	return __do_kmalloc_node(size, gfp, NUMA_NO_NODE, _RET_IP_);
}
EXPORT_SYMBOL(__kmalloc);

void *__kmalloc_track_caller(size_t size, gfp_t gfp, unsigned long caller)
{
	return __do_kmalloc_node(size, gfp, NUMA_NO_NODE, caller);
}

#ifdef CONFIG_NUMA
void *__kmalloc_node_track_caller(size_t size, gfp_t gfp,
					int node, unsigned long caller)
{
	return __do_kmalloc_node(size, gfp, node, caller);
}
#endif

void kfree(const void *block)
{
	struct page *sp;

	trace_kfree(_RET_IP_, block);

	if (unlikely(ZERO_OR_NULL_PTR(block)))
		return;
	kmemleak_free(block);

	VM_BUG_ON(!virt_addr_valid(block));
	sp = virt_to_head_page(block);
	BUG_ON(virt_to_page(block) != sp);
	VM_BUG_ON(!PageSlab(sp));
	if (!sp->private) {
		int align = max_t(size_t, ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MINALIGN);
		slob_t *m = (slob_t *)(block - align);

		BUG_ON(sp->units < 0);
		slob_free(NULL, m, m[0].units + align);
	} else {
		__ClearPageSlab(sp);
		page_mapcount_reset(sp);
		sp->private = 0;
		__free_pages(sp, compound_order(sp));
	}
}
EXPORT_SYMBOL(kfree);

bool is_usercopy_object(const void *ptr)
{
	struct page *page;

	if (ZERO_OR_NULL_PTR(ptr))
		return false;

	if (!slab_is_available())
		return false;

	if (is_vmalloc_addr(ptr)
#ifdef CONFIG_GRKERNSEC_KSTACKOVERFLOW
	    && !object_starts_on_stack(ptr)
#endif
	) {
		struct vm_struct *vm = find_vm_area(ptr);
		if (vm && (vm->flags & VM_USERCOPY))
			return true;
		return false;
	}

	if (!virt_addr_valid(ptr))
		return false;

	page = virt_to_head_page(ptr);
	BUG_ON(virt_to_page(ptr) != page);

	if (!PageSlab(page))
		return false;

	// PAX: TODO check SLAB_USERCOPY

	return false;
}

#ifdef CONFIG_HARDENED_USERCOPY
const char *__check_heap_object(const void *ptr, unsigned long n,
				struct page *page)
{
	const slob_t *free;
	const void *base;
	unsigned long flags;

	BUG_ON(virt_to_page(ptr) != page);

	if (page->private) {
		base = page_address(page);
		if (base <= ptr && n <= page->private - (ptr - base))
			return NULL;
		return "<slob 1>";
	}

	/* some tricky double walking to find the chunk */
	spin_lock_irqsave(&slob_lock, flags);
	base = (const void *)((unsigned long)ptr & PAGE_MASK);
	free = page->freelist;

	while (!slob_last(free) && (const void *)free <= ptr) {
		base = free + slob_units(free);
		free = slob_next(free);
	}

	while (base < (const void *)free) {
		slobidx_t m = ((slob_t *)base)[0].units, align = ((slob_t *)base)[1].units;
		int size = SLOB_UNIT * SLOB_UNITS(m + align);
		int offset;

		if (ptr < base + align)
			break;

		offset = ptr - base - align;
		if (offset >= m) {
			base += size;
			continue;
		}

		if (n > m - offset)
			break;

		spin_unlock_irqrestore(&slob_lock, flags);
		return NULL;
	}

	spin_unlock_irqrestore(&slob_lock, flags);
	return "<slob 2>";
}
#endif

/* can't use ksize for kmem_cache_alloc memory, only kmalloc */
size_t ksize(const void *block)
{
	struct page *sp;
	int align;
	slob_t *m;

	BUG_ON(!block);
	if (unlikely(block == ZERO_SIZE_PTR))
		return 0;

	sp = virt_to_head_page(block);
	BUG_ON(virt_to_page(block) != sp);
	VM_BUG_ON(!PageSlab(sp));
	if (sp->private)
		return sp->private;

	align = max_t(size_t, ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MINALIGN);
	m = (slob_t *)(block - align);
	return SLOB_UNITS(m[0].units) * SLOB_UNIT;
}
EXPORT_SYMBOL(ksize);

int __kmem_cache_create(struct kmem_cache *c, unsigned long flags)
{
	flags = pax_sanitize_slab_flags(flags);

	if (flags & SLAB_DESTROY_BY_RCU) {
		/* leave room for rcu footer at the end of object */
		c->size += sizeof(struct slob_rcu);
	}
	c->flags = flags;
	return 0;
}

static void *slob_alloc_node(struct kmem_cache *c, gfp_t flags, int node)
{
	void *b = NULL;

	flags &= gfp_allowed_mask;

	lockdep_trace_alloc(flags);

#ifdef CONFIG_PAX_USERCOPY
	b = __do_kmalloc_node_align(c->size, flags, node, _RET_IP_, c->align);
#else
	if (c->size < PAGE_SIZE) {
		b = slob_alloc(c->size, flags, c->align, node);
		trace_kmem_cache_alloc_node(_RET_IP_, b, c->object_size,
					    SLOB_UNITS(c->size) * SLOB_UNIT,
					    flags, node);
	} else {
		struct page *sp;

		sp = slob_new_pages(flags, get_order(c->size), node);
		if (sp) {
			b = page_address(sp);
			sp->private = c->size;
		}
		trace_kmem_cache_alloc_node(_RET_IP_, b, c->object_size,
					    PAGE_SIZE << get_order(c->size),
					    flags, node);
	}
#endif

	if (b && c->ctor)
		c->ctor(b);

	kmemleak_alloc_recursive(b, c->size, 1, c->flags, flags);
	return b;
}

void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	return slob_alloc_node(cachep, flags, NUMA_NO_NODE);
}
EXPORT_SYMBOL(kmem_cache_alloc);

#ifdef CONFIG_NUMA
void * __size_overflow(1) __kmalloc_node(size_t size, gfp_t gfp, int node)
{
	return __do_kmalloc_node(size, gfp, node, _RET_IP_);
}
EXPORT_SYMBOL(__kmalloc_node);

void *kmem_cache_alloc_node(struct kmem_cache *cachep, gfp_t gfp, int node)
{
	return slob_alloc_node(cachep, gfp, node);
}
EXPORT_SYMBOL(kmem_cache_alloc_node);
#endif

static void __kmem_cache_free(struct kmem_cache *c, void *b, int size)
{
	struct page *sp;

	BUG_ON(virt_to_page(b) != virt_to_head_page(b));
	sp = virt_to_head_page(b);
	BUG_ON(!PageSlab(sp));
	if (!sp->private)
		slob_free(c, b, size);
	else
		slob_free_pages(sp, get_order(size));
}

static void kmem_rcu_free(struct rcu_head *head)
{
	struct slob_rcu *slob_rcu = (struct slob_rcu *)head;
	void *b = (void *)slob_rcu - (slob_rcu->size - sizeof(struct slob_rcu));

	__kmem_cache_free(NULL, b, slob_rcu->size);
}

void kmem_cache_free(struct kmem_cache *c, void *b)
{
	int size = c->size;

#ifdef CONFIG_PAX_USERCOPY
	if (size + c->align < PAGE_SIZE) {
		size += c->align;
		b -= c->align;
	}
#endif

	kmemleak_free_recursive(b, c->flags);
	if (unlikely(c->flags & SLAB_DESTROY_BY_RCU)) {
		struct slob_rcu *slob_rcu;
		slob_rcu = b + (size - sizeof(struct slob_rcu));
		slob_rcu->size = size;
		call_rcu(&slob_rcu->head, kmem_rcu_free);
	} else {
		__kmem_cache_free(c, b, size);
	}

#ifdef CONFIG_PAX_USERCOPY
	trace_kfree(_RET_IP_, b);
#else
	trace_kmem_cache_free(_RET_IP_, b);
#endif

}
EXPORT_SYMBOL(kmem_cache_free);

void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
{
	__kmem_cache_free_bulk(s, size, p);
}
EXPORT_SYMBOL(kmem_cache_free_bulk);

int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
								void **p)
{
	return __kmem_cache_alloc_bulk(s, flags, size, p);
}
EXPORT_SYMBOL(kmem_cache_alloc_bulk);

int __kmem_cache_shutdown(struct kmem_cache *c)
{
	/* No way to check for remaining objects */
	return 0;
}

void __kmem_cache_release(struct kmem_cache *c)
{
}

int __kmem_cache_shrink(struct kmem_cache *d)
{
	return 0;
}

struct kmem_cache kmem_cache_boot = {
	.name = "kmem_cache",
	.size = sizeof(struct kmem_cache),
	.flags = SLAB_PANIC,
	.align = ARCH_KMALLOC_MINALIGN,
};

void __init kmem_cache_init(void)
{
	kmem_cache = &kmem_cache_boot;
	slab_state = UP;
}

void __init kmem_cache_init_late(void)
{
	slab_state = FULL;
}
