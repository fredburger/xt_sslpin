/*
 * hexutils.h
 *
 * Copyright (C) 2010-2013 fredburger (github.com/fredburger)
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef _LINUX_NETFILTER_XT_SSLPIN_HEXUTILS_H
#define _LINUX_NETFILTER_XT_SSLPIN_HEXUTILS_H


#include "xt_sslpin.h"


/* hex char to int, or 16 on invalid char - branching (no lookup table) */
static inline __u8 hexc2int(const char c)
{
    if ((c <= '9') && (c >= '0')) { return c - '0'; }
    if ((c >= 'a') && (c <= 'f')) { return c - 'a' + 10; }
    if ((c >= 'A') && (c <= 'Z')) { return c - 'A' + 10; }
    return 16;
}


/* print byte array as hex */
static void printhex(const __u8 *bytes, __u32 len)
{
    const char hextab[] = "0123456789abcdef";
    const __u8 * const bytes_end = bytes + len;
    char hexbuf[512 - 1];
    char *hexp;
    const __u8 *bytes_max;

    while (bytes < bytes_end) {
        bytes_max = bytes + ((sizeof(hexbuf) - 1) >> 1);
        if (bytes_max > bytes_end) {
            bytes_max = bytes_end;
        }
        for (hexp = hexbuf; bytes < bytes_max; bytes++) {
            *hexp++ = hextab[*bytes >> 4];
            *hexp++ = hextab[*bytes & 15];
        }
        *hexp = 0;

        #ifdef __KERNEL__
            printk("%s", hexbuf);
        #else
            printf("%s", hexbuf);
        #endif
    }
}


#endif /* _LINUX_NETFILTER_XT_SSLPIN_HEXUTILS_H */
