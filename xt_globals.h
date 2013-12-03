/*
 * xt_globals.h
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

#ifndef _LINUX_NETFILTER_XT_SSLPIN_GLOBALS_H
#define _LINUX_NETFILTER_XT_SSLPIN_GLOBALS_H


static DEFINE_SPINLOCK( sslpin_mt_lock);
static bool             sslpin_mt_has_debug_rules               __read_mostly  = false;
static bool             sslpin_mt_checked_after_destroy         = false;


#endif /* _LINUX_NETFILTER_XT_SSLPIN_GLOBALS_H */
