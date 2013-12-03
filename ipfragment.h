/*
 * ipfragment.h
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

#ifndef _LINUX_NETFILTER_XT_SSLPIN_IPFRAGMENT_H
#define _LINUX_NETFILTER_XT_SSLPIN_IPFRAGMENT_H


#ifndef IP_MF
#define IP_MF       0x2000      /* Flag: "More Fragments"   */
#endif

#ifndef IP_OFFSET
#define IP_OFFSET   0x1FFF      /* "Fragment Offset" part   */
#endif


static inline bool is_ip_fragment(__u16 frag_off)
{
    return (frag_off & htons(IP_MF | IP_OFFSET)) != 0;
}


#endif /* _LINUX_NETFILTER_XT_SSLPIN_IPFRAGMENT_H */
