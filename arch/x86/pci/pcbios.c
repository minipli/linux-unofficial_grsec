/*
 * BIOS32 and PCI BIOS handling.
 */

#include <linux/pci.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <asm/pci_x86.h>
#include <asm/pci-functions.h>
#include <asm/cacheflush.h>

/* BIOS32 signature: "_32_" */
#define BIOS32_SIGNATURE	(('_' << 0) + ('3' << 8) + ('2' << 16) + ('_' << 24))

/* PCI signature: "PCI " */
#define PCI_SIGNATURE		(('P' << 0) + ('C' << 8) + ('I' << 16) + (' ' << 24))

/* PCI service signature: "$PCI" */
#define PCI_SERVICE		(('$' << 0) + ('P' << 8) + ('C' << 16) + ('I' << 24))

/* PCI BIOS hardware mechanism flags */
#define PCIBIOS_HW_TYPE1		0x01
#define PCIBIOS_HW_TYPE2		0x02
#define PCIBIOS_HW_TYPE1_SPEC		0x10
#define PCIBIOS_HW_TYPE2_SPEC		0x20

int pcibios_enabled;

/* According to the BIOS specification at:
 * http://members.datafast.net.au/dft0802/specs/bios21.pdf, we could
 * restrict the x zone to some pages and make it ro. But this may be
 * broken on some bios, complex to handle with static_protections.
 * We could make the 0xe0000-0x100000 range rox, but this can break
 * some ISA mapping.
 *
 * So we let's an rw and x hole when pcibios is used. This shouldn't
 * happen for modern system with mmconfig, and if you don't want it
 * you could disable pcibios...
 */
static inline void set_bios_x(void)
{
	pcibios_enabled = 1;
	set_memory_x(PAGE_OFFSET + BIOS_BEGIN, (BIOS_END - BIOS_BEGIN) >> PAGE_SHIFT);
	if (__supported_pte_mask & _PAGE_NX)
		printk(KERN_INFO "PCI : PCI BIOS area is rw and x. Use pci=nobios if you want it NX.\n");
}

/*
 * This is the standard structure used to identify the entry point
 * to the BIOS32 Service Directory, as documented in
 * 	Standard BIOS 32-bit Service Directory Proposal
 * 	Revision 0.4 May 24, 1993
 * 	Phoenix Technologies Ltd.
 *	Norwood, MA
 * and the PCI BIOS specification.
 */

union bios32 {
	struct {
		unsigned long signature;	/* _32_ */
		unsigned long entry;		/* 32 bit physical address */
		unsigned char revision;		/* Revision level, 0 */
		unsigned char length;		/* Length in paragraphs should be 01 */
		unsigned char checksum;		/* All bytes must add up to zero */
		unsigned char reserved[5]; 	/* Must be zero */
	} fields;
	char chars[16];
};

/*
 * Physical address of the service directory.  I don't know if we're
 * allowed to have more than one of these or not, so just in case
 * we'll make pcibios_present() take a memory start parameter and store
 * the array there.
 */

static struct {
	unsigned long address;
	unsigned short segment;
} bios32_indirect __initdata = { 0, __PCIBIOS_CS };

/*
 * Returns the entry point for the given service, NULL on error
 */

static unsigned long __init bios32_service(unsigned long service)
{
	unsigned char return_code;	/* %al */
	unsigned long address;		/* %ebx */
	unsigned long length;		/* %ecx */
	unsigned long entry;		/* %edx */
	unsigned long flags;
	struct desc_struct d, *gdt;

	local_irq_save(flags);

	gdt = get_cpu_gdt_table(smp_processor_id());

	pack_descriptor(&d, 0UL, 0xFFFFFUL, 0x9B, 0xC);
	write_gdt_entry(gdt, GDT_ENTRY_PCIBIOS_CS, &d, DESCTYPE_S);
	pack_descriptor(&d, 0UL, 0xFFFFFUL, 0x93, 0xC);
	write_gdt_entry(gdt, GDT_ENTRY_PCIBIOS_DS, &d, DESCTYPE_S);

	__asm__("movw %w7, %%ds; lcall *(%%edi); push %%ss; pop %%ds; cld"
		: "=a" (return_code),
		  "=b" (address),
		  "=c" (length),
		  "=d" (entry)
		: "0" (service),
		  "1" (0),
		  "D" (&bios32_indirect),
		  "r"(__PCIBIOS_DS)
		: "memory");

	pax_open_kernel();
	gdt[GDT_ENTRY_PCIBIOS_CS].a = 0;
	gdt[GDT_ENTRY_PCIBIOS_CS].b = 0;
	gdt[GDT_ENTRY_PCIBIOS_DS].a = 0;
	gdt[GDT_ENTRY_PCIBIOS_DS].b = 0;
	pax_close_kernel();

	local_irq_restore(flags);

	switch (return_code) {
	case 0: {
		int cpu;
		unsigned char flags;

		printk(KERN_INFO "bios32_service: base:%08lx length:%08lx entry:%08lx\n", address, length, entry);
		if (address >= 0xFFFF0 || length > 0x100000 - address || length <= entry) {
			printk(KERN_WARNING "bios32_service: not valid\n");
			return 0;
		}
		address = address + PAGE_OFFSET;
		length += 16UL; /* some BIOSs underreport this... */
		flags = 4;
		if (length >= 64*1024*1024) {
			length >>= PAGE_SHIFT;
			flags |= 8;
		}

		for (cpu = 0; cpu < nr_cpu_ids; cpu++) {
			gdt = get_cpu_gdt_table(cpu);
			pack_descriptor(&d, address, length, 0x9b, flags);
			write_gdt_entry(gdt, GDT_ENTRY_PCIBIOS_CS, &d, DESCTYPE_S);
			pack_descriptor(&d, address, length, 0x93, flags);
			write_gdt_entry(gdt, GDT_ENTRY_PCIBIOS_DS, &d, DESCTYPE_S);
		}
		return entry;
	}
	case 0x80:	/* Not present */
		printk(KERN_WARNING "bios32_service(0x%lx): not present\n", service);
		return 0;
	default: /* Shouldn't happen */
		printk(KERN_WARNING "bios32_service(0x%lx): returned 0x%x -- BIOS bug!\n",
			service, return_code);
		return 0;
	}
}

static struct {
	unsigned long address;
	unsigned short segment;
} pci_indirect __ro_after_init = {
	.address = 0,
	.segment = __PCIBIOS_CS,
};

static int pci_bios_present __ro_after_init;

static int __init check_pcibios(void)
{
	u32 signature, eax, ebx, ecx;
	u8 status, major_ver, minor_ver, hw_mech;
	unsigned long flags, pcibios_entry;

	if ((pcibios_entry = bios32_service(PCI_SERVICE))) {
		pci_indirect.address = pcibios_entry;

		local_irq_save(flags);
		__asm__("movw %w6, %%ds\n\t"
			"lcall *%%ss:(%%edi); cld\n\t"
			"push %%ss\n\t"
			"pop %%ds\n\t"
			"jc 1f\n\t"
			"xor %%ah, %%ah\n"
			"1:"
			: "=d" (signature),
			  "=a" (eax),
			  "=b" (ebx),
			  "=c" (ecx)
			: "1" (PCIBIOS_PCI_BIOS_PRESENT),
			  "D" (&pci_indirect),
			  "r" (__PCIBIOS_DS)
			: "memory");
		local_irq_restore(flags);

		status = (eax >> 8) & 0xff;
		hw_mech = eax & 0xff;
		major_ver = (ebx >> 8) & 0xff;
		minor_ver = ebx & 0xff;
		if (pcibios_last_bus < 0)
			pcibios_last_bus = ecx & 0xff;
		DBG("PCI: BIOS probe returned s=%02x hw=%02x ver=%02x.%02x l=%02x\n",
			status, hw_mech, major_ver, minor_ver, pcibios_last_bus);
		if (status || signature != PCI_SIGNATURE) {
			printk (KERN_ERR "PCI: BIOS BUG #%x[%08x] found\n",
				status, signature);
			return 0;
		}
		printk(KERN_INFO "PCI: PCI BIOS revision %x.%02x entry at 0x%lx, last bus=%d\n",
			major_ver, minor_ver, pcibios_entry, pcibios_last_bus);
#ifdef CONFIG_PCI_DIRECT
		if (!(hw_mech & PCIBIOS_HW_TYPE1))
			pci_probe &= ~PCI_PROBE_CONF1;
		if (!(hw_mech & PCIBIOS_HW_TYPE2))
			pci_probe &= ~PCI_PROBE_CONF2;
#endif
		return 1;
	}
	return 0;
}

static int pci_bios_read(unsigned int seg, unsigned int bus,
			 unsigned int devfn, int reg, int len, u32 *value)
{
	unsigned long result = 0;
	unsigned long flags;
	unsigned long bx = (bus << 8) | devfn;
	u16 number = 0, mask = 0;

	WARN_ON(seg);
	if (!value || (bus > 255) || (devfn > 255) || (reg > 255))
		return -EINVAL;

	raw_spin_lock_irqsave(&pci_config_lock, flags);

	switch (len) {
	case 1:
		number = PCIBIOS_READ_CONFIG_BYTE;
		mask = 0xff;
		break;
	case 2:
		number = PCIBIOS_READ_CONFIG_WORD;
		mask = 0xffff;
		break;
	case 4:
		number = PCIBIOS_READ_CONFIG_DWORD;
		break;
	}

	__asm__("movw %w6, %%ds\n\t"
		"lcall *%%ss:(%%esi); cld\n\t"
		"push %%ss\n\t"
		"pop %%ds\n\t"
		"jc 1f\n\t"
		"xor %%ah, %%ah\n"
		"1:"
		: "=c" (*value),
		  "=a" (result)
		: "1" (number),
		  "b" (bx),
		  "D" ((long)reg),
		  "S" (&pci_indirect),
		  "r" (__PCIBIOS_DS));
	/*
	 * Zero-extend the result beyond 8 or 16 bits, do not trust the
	 * BIOS having done it:
	 */
	if (mask)
		*value &= mask;

	raw_spin_unlock_irqrestore(&pci_config_lock, flags);

	return (int)((result & 0xff00) >> 8);
}

static int pci_bios_write(unsigned int seg, unsigned int bus,
			  unsigned int devfn, int reg, int len, u32 value)
{
	unsigned long result = 0;
	unsigned long flags;
	unsigned long bx = (bus << 8) | devfn;
	u16 number = 0;

	WARN_ON(seg);
	if ((bus > 255) || (devfn > 255) || (reg > 255)) 
		return -EINVAL;

	raw_spin_lock_irqsave(&pci_config_lock, flags);

	switch (len) {
	case 1:
		number = PCIBIOS_WRITE_CONFIG_BYTE;
		break;
	case 2:
		number = PCIBIOS_WRITE_CONFIG_WORD;
		break;
	case 4:
		number = PCIBIOS_WRITE_CONFIG_DWORD;
		break;
	}

	__asm__("movw %w6, %%ds\n\t"
		"lcall *%%ss:(%%esi); cld\n\t"
		"push %%ss\n\t"
		"pop %%ds\n\t"
		"jc 1f\n\t"
		"xor %%ah, %%ah\n"
		"1:"
		: "=a" (result)
		: "0" (number),
		  "c" (value),
		  "b" (bx),
		  "D" ((long)reg),
		  "S" (&pci_indirect),
		  "r" (__PCIBIOS_DS));

	raw_spin_unlock_irqrestore(&pci_config_lock, flags);

	return (int)((result & 0xff00) >> 8);
}


/*
 * Function table for BIOS32 access
 */

static const struct pci_raw_ops pci_bios_access = {
	.read =		pci_bios_read,
	.write =	pci_bios_write
};

/*
 * Try to find PCI BIOS.
 */

static const struct pci_raw_ops *__init pci_find_bios(void)
{
	union bios32 *check;
	unsigned char sum;
	int i, length;

	/*
	 * Follow the standard procedure for locating the BIOS32 Service
	 * directory by scanning the permissible address range from
	 * 0xe0000 through 0xfffff for a valid BIOS32 structure.
	 */

	for (check = (union bios32 *) __va(0xe0000);
	     check <= (union bios32 *) __va(0xffff0);
	     ++check) {
		long sig;
		if (probe_kernel_address(&check->fields.signature, sig))
			continue;

		if (check->fields.signature != BIOS32_SIGNATURE)
			continue;
		length = check->fields.length * 16;
		if (!length)
			continue;
		sum = 0;
		for (i = 0; i < length ; ++i)
			sum += check->chars[i];
		if (sum != 0)
			continue;
		if (check->fields.revision != 0) {
			printk("PCI: unsupported BIOS32 revision %d at 0x%p\n",
				check->fields.revision, check);
			continue;
		}
		DBG("PCI: BIOS32 Service Directory structure at 0x%p\n", check);
		if (check->fields.entry >= 0x100000) {
			printk("PCI: BIOS32 entry (0x%p) in high memory, "
					"cannot use.\n", check);
			return NULL;
		} else {
			unsigned long bios32_entry = check->fields.entry;
			DBG("PCI: BIOS32 Service Directory entry at 0x%lx\n",
					bios32_entry);
			bios32_indirect.address = bios32_entry + PAGE_OFFSET;
			set_bios_x();
			if (check_pcibios())
				return &pci_bios_access;
		}
		break;	/* Hopefully more than one BIOS32 cannot happen... */
	}

	return NULL;
}

/*
 *  BIOS Functions for IRQ Routing
 */

struct irq_routing_options {
	u16 size;
	struct irq_info *table;
	u16 segment;
} __attribute__((packed));

struct irq_routing_table * pcibios_get_irq_routing_table(void)
{
	struct irq_routing_options opt;
	struct irq_routing_table *rt = NULL;
	int ret, map;
	unsigned long page;

	if (!pci_bios_present)
		return NULL;
	page = __get_free_page(GFP_KERNEL);
	if (!page)
		return NULL;
	opt.table = (struct irq_info *) page;
	opt.size = PAGE_SIZE;
	opt.segment = __KERNEL_DS;

	DBG("PCI: Fetching IRQ routing table... ");
	__asm__("push %%es\n\t"
		"movw %w8, %%ds\n\t"
		"push %%ds\n\t"
		"pop  %%es\n\t"
		"lcall *%%ss:(%%esi); cld\n\t"
		"pop %%es\n\t"
		"push %%ss\n\t"
		"pop %%ds\n"
		"jc 1f\n\t"
		"xor %%ah, %%ah\n"
		"1:"
		: "=a" (ret),
		  "=b" (map),
		  "=m" (opt)
		: "0" (PCIBIOS_GET_ROUTING_OPTIONS),
		  "1" (0),
		  "D" ((long) &opt),
		  "S" (&pci_indirect),
		  "m" (opt),
		  "r" (__PCIBIOS_DS)
		: "memory");
	DBG("OK  ret=%d, size=%d, map=%x\n", ret, opt.size, map);
	if (ret & 0xff00)
		printk(KERN_ERR "PCI: Error %02x when fetching IRQ routing table.\n", (ret >> 8) & 0xff);
	else if (opt.size) {
		rt = kmalloc(sizeof(struct irq_routing_table) + opt.size, GFP_KERNEL);
		if (rt) {
			memset(rt, 0, sizeof(struct irq_routing_table));
			rt->size = opt.size + sizeof(struct irq_routing_table);
			rt->exclusive_irqs = map;
			memcpy(rt->slots, (void *) page, opt.size);
			printk(KERN_INFO "PCI: Using BIOS Interrupt Routing Table\n");
		}
	}
	free_page(page);
	return rt;
}
EXPORT_SYMBOL(pcibios_get_irq_routing_table);

int pcibios_set_irq_routing(struct pci_dev *dev, int pin, int irq)
{
	int ret;

	__asm__("movw %w5, %%ds\n\t"
		"lcall *%%ss:(%%esi); cld\n\t"
		"push %%ss\n\t"
		"pop %%ds\n"
		"jc 1f\n\t"
		"xor %%ah, %%ah\n"
		"1:"
		: "=a" (ret)
		: "0" (PCIBIOS_SET_PCI_HW_INT),
		  "b" ((dev->bus->number << 8) | dev->devfn),
		  "c" ((irq << 8) | (pin + 10)),
		  "S" (&pci_indirect),
		  "r" (__PCIBIOS_DS));
	return !(ret & 0xff00);
}
EXPORT_SYMBOL(pcibios_set_irq_routing);

void __init pci_pcbios_init(void)
{
	if ((pci_probe & PCI_PROBE_BIOS) 
		&& ((raw_pci_ops = pci_find_bios()))) {
		pci_bios_present = 1;
	}
}

