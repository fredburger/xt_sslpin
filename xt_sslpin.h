/*
 * xt_sslpin.h
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

#ifndef _LINUX_NETFILTER_XT_SSLPIN_H
#define _LINUX_NETFILTER_XT_SSLPIN_H


/* buffer constraints */
#define SSLPIN_MAX_COMMON_NAME_UTF8_BYTELEN         (48 - 1)
#define SSLPIN_MAX_PUBLIC_KEY_BYTELEN               528
#define SSLPIN_MAX_PUBLIC_KEY_ALG_OID_BYTELEN       12
#define SSLPIN_MIN_PUBLIC_KEY_BYTELEN               32


/* xt_sslpin rule flags */
typedef enum {
    SSLPIN_RULE_FLAG_DEBUG        = 1 << 0,
    SSLPIN_RULE_FLAG_INVERT       = 1 << 1,
} sslpin_rule_flags_t;


/* X509 Public Key Algorithm identifiers */
struct sslpin_pubkeyalg {
    char name[4];
    __u8 oid_asn1[SSLPIN_MAX_PUBLIC_KEY_ALG_OID_BYTELEN];
} __attribute__((aligned(8)));


static const struct sslpin_pubkeyalg pubkeyalgs[] = {
    { .name = "rsa",    .oid_asn1 = { 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01  } },
    { .name = "ec",     .oid_asn1 = { 7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 } },
    { .name = "dsa",    .oid_asn1 = { 7, 0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01 } },
};

#define SSLPIN_PUBLIC_KEY_ALGS_CNT          (sizeof(pubkeyalgs) / sizeof(struct sslpin_pubkeyalg))


/* xt_sslpin kernel module data
   shared between kernel & userspace up until kernpriv struct (kernel-only private data)
   per rule */
struct sslpin_mtruleinfo {
    sslpin_rule_flags_t         flags;
    __u32                       pk_len;
    __u8                        pk[SSLPIN_MAX_PUBLIC_KEY_BYTELEN];
    __u32                       cn_len;
    char                        cn[SSLPIN_MAX_COMMON_NAME_UTF8_BYTELEN + 1];
    struct sslpin_pubkeyalg     pk_alg;

    struct {
    } kernpriv __attribute__((aligned(8)));
};


#define SSLPIN_MTRULEINFO_KERN_SIZE      XT_ALIGN(sizeof(struct sslpin_mtruleinfo))
#define SSLPIN_MTRULEINFO_USER_SIZE      offsetof(struct sslpin_mtruleinfo, kernpriv)


static inline bool sslpin_debug_enabled(const struct sslpin_mtruleinfo *mtruleinfo) {
    return mtruleinfo->flags & SSLPIN_RULE_FLAG_DEBUG;
}

static inline bool sslpin_pubkeyalg_equalnames(const struct sslpin_pubkeyalg * const alg1,
            const struct sslpin_pubkeyalg * const alg2)
{
    if ((!alg1) || (!alg2)) {
        return false;
    }
    return (alg1->name[0] == alg2->name[0])
        && (alg1->name[1] == alg2->name[1])
        && (alg1->name[2] == alg2->name[2])
        && (alg1->name[3] == alg2->name[3]);
}


#endif /* _LINUX_NETFILTER_XT_SSLPIN_H */
