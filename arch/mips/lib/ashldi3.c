#include <linux/export.h>

#include "libgcc.h"

#ifdef CONFIG_64BIT
DWtype notrace __ashlti3(DWtype u, word_type b)
#else
DWtype notrace __ashldi3(DWtype u, word_type b)
#endif
{
	DWunion uu, w;
	word_type bm;

	if (b == 0)
		return u;

	uu.ll = u;
	bm = BITS_PER_LONG - b;

	if (bm <= 0) {
		w.s.low = 0;
		w.s.high = (unsigned long) uu.s.low << -bm;
	} else {
		const unsigned long carries = (unsigned long) uu.s.low >> bm;

		w.s.low = (unsigned long) uu.s.low << b;
		w.s.high = ((unsigned long) uu.s.high << b) | carries;
	}

	return w.ll;
}
#ifdef CONFIG_64BIT
EXPORT_SYMBOL(__ashlti3);
#else
EXPORT_SYMBOL(__ashldi3);
#endif
