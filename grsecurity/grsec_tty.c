#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/grsecurity.h>
#include <linux/grinternal.h>
#include <linux/capability.h>
#include <linux/tty.h>

int gr_handle_tiocsti(struct tty_struct *tty)
{
#ifdef CONFIG_GRKERNSEC_HARDEN_TTY
	if (grsec_enable_harden_tty && (current->signal->tty == tty) &&
	    !capable(CAP_SYS_ADMIN)) {
		gr_log_noargs(GR_DONT_AUDIT, GR_TIOCSTI_MSG);
		return 1;
	}
#endif
	return 0;
}
