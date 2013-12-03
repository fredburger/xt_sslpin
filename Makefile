#
# xt_sslpin makefile
#
# Copyright (C) 2010-2013 fredburger (github.com/fredburger)
#
# This program is free software; you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, write to
# the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#

# Detect libdir: /lib vs. /lib64
libdir.x86_64 = /lib64
libdir.i686 = /lib
libdir = $(libdir.$(shell uname -m))

# System configuration
MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := $(MODULES_DIR)/build
# XTABLES_DIR := $(libdir)/xtables
XTABLES_DIR := $(libdir.i686)/xtables

# --
LIB_INSTALLPATH := $(XTABLES_DIR)/libxt_sslpin.so
MOD_INSTALLPATH := $(MODULES_DIR)/extra/xt_sslpin.ko

CLIBFLAGS := -O2 -Wall -fPIC

obj-m := xt_sslpin.o


lib%.so: lib%.o
	$(CC) -shared -o $@ $^;

lib%.o: lib%.c
	$(CC) $(CLIBFLAGS) -D_INIT=lib$*_init -c -o $@ $<;

all:		libxt_sslpin.so
	make -C $(KERNEL_DIR) M=$$PWD;

modules:
	make -C $(KERNEL_DIR) M=$$PWD $@;

modules_install:
	make -C $(KERNEL_DIR) M=$$PWD $@;

install:	log_install all modules_install
	depmod -a
	install -p -m 0644 libxt_sslpin.so $(XTABLES_DIR)
	@echo "\nINSTALLED\n"
	modinfo xt_sslpin
	@echo
	@echo "libxt_sslpin.so:"
	@ls -al $(LIB_INSTALLPATH)
	@echo

uninstall:	log_install
	@if [ -f $(MOD_INSTALLPATH) ]; then         \
		modprobe -r xt_sslpin     &&            \
		rm -f $(MOD_INSTALLPATH)  &&            \
		depmod -a;                              \
	fi
	@if [ -f $(LIB_INSTALLPATH) ]; then         \
		rm -f /test; \
	fi
	@echo "\nUNINSTALLED\n"

clean:
	make -C $(KERNEL_DIR) M=$$PWD $@;
	@rm -f libxt_sslpin.so

log_install:
	@echo "\nMODULES_DIR: $(MODULES_DIR)\nKERNEL_DIR:  $(KERNEL_DIR)\nXTABLES_DIR: $(XTABLES_DIR)\n"
