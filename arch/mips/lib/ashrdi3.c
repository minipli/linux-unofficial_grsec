#include <linux/export.h>

#include "libgcc.h"

#ifdef CONFIG_64BIT
DWtype notrace __ashrti3(DWtype u, word_type b)
#else
DWtype notrace __ashrdi3(DWtype u, word_type b)
#endif
{
	DWunion uu, w;
	word_type bm;

	if (b == 0)
		return u;

	uu.ll = u;
	bm = BITS_PER_LONG - b;

	if (bm <= 0) {
		/* w.s.high = 1..1 or 0..0 */
		w.s.high =
		    uu.s.high >> (BITS_PER_LONG - 1);
		w.s.low = uu.s.high >> -bm;
	} else {
		const unsigned long carries = (unsigned long) uu.s.high << bm;

		w.s.high = uu.s.high >> b;
		w.s.low = ((unsigned long) uu.s.low >> b) | carries;
	}

	return w.ll;
}
#ifdef CONFIG_64BIT
EXPORT_SYMBOL(__ashrti3);
#else
EXPORT_SYMBOL(__ashrdi3);
#endif
