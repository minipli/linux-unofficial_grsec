#include <linux/kernel.h>
#include <linux/grinternal.h>
#include <linux/module.h>

int gr_handle_new_usb(void)
{
#ifdef CONFIG_GRKERNSEC_DENYUSB
	if (grsec_deny_new_usb) {
		printk(KERN_ALERT "grsec: denied insert of new USB device\n");
		return 1;
	}
#endif
	return 0;
}
EXPORT_SYMBOL_GPL(gr_handle_new_usb);
