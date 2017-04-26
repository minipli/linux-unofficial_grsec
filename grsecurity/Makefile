# grsecurity - access control and security hardening for Linux
# All code in this directory and various hooks located throughout the Linux kernel are
# Copyright (C) 2001-2014 Bradley Spengler, Open Source Security, Inc.
# http://www.grsecurity.net spender@grsecurity.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

KBUILD_CFLAGS += -Werror

obj-y = grsec_chdir.o grsec_chroot.o grsec_exec.o grsec_fifo.o grsec_fork.o \
	grsec_mount.o grsec_sig.o grsec_sysctl.o \
	grsec_time.o grsec_tpe.o grsec_link.o grsec_pax.o grsec_ptrace.o \
	grsec_usb.o grsec_ipc.o grsec_proc.o grsec_tty.o

obj-$(CONFIG_GRKERNSEC) += grsec_init.o grsum.o gracl.o gracl_segv.o \
	gracl_cap.o gracl_alloc.o gracl_shm.o grsec_mem.o gracl_fs.o \
	gracl_learn.o grsec_log.o gracl_policy.o
ifdef CONFIG_COMPAT
obj-$(CONFIG_GRKERNSEC) += gracl_compat.o
endif

obj-$(CONFIG_GRKERNSEC_RESLOG) += gracl_res.o

ifdef CONFIG_NET
obj-y += grsec_sock.o
obj-$(CONFIG_GRKERNSEC) += gracl_ip.o
endif

ifndef CONFIG_GRKERNSEC
obj-y += grsec_disabled.o
endif

ifdef CONFIG_GRKERNSEC_HIDESYM
extra-y := grsec_hidesym.o
$(obj)/grsec_hidesym.o:
	@-chmod -f 500 /boot
	@-chmod -f 500 /lib/modules
	@-chmod -f 500 /lib64/modules
	@-chmod -f 500 /lib32/modules
	@-chmod -f 700 .
	@-chmod -f 700 $(objtree)
	@echo '  grsec: protected kernel image paths'
endif
