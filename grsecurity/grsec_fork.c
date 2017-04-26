#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/grsecurity.h>
#include <linux/grinternal.h>
#include <linux/errno.h>

void
gr_log_forkfail(const int retval)
{
#ifdef CONFIG_GRKERNSEC_FORKFAIL
	if (grsec_enable_forkfail && (retval == -EAGAIN || retval == -ENOMEM)) {
		switch (retval) {
			case -EAGAIN:
				gr_log_str(GR_DONT_AUDIT, GR_FAILFORK_MSG, "EAGAIN");
				break;
			case -ENOMEM:
				gr_log_str(GR_DONT_AUDIT, GR_FAILFORK_MSG, "ENOMEM");
				break;
		}
	}
#endif
	return;
}
