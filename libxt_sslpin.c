/*
 * libxt_sslpin.c
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

#include <xtables.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "xt_sslpin.h"
#include "hexutils.h"


/* parameter definitions */
static const struct option sslpin_mt_opts[] = {
    { .name = "pubkey",     .has_arg = true,    .val = 'p' },
    { .name = "debug",      .has_arg = false,   .val = 'd' },
    { NULL },
};


/* parse pubkey option (<alg>:<key-hex>) */
static bool parse_pubkey_opt(struct sslpin_mtruleinfo *mtruleinfo, char *optarg)
{
    const struct sslpin_pubkeyalg *pubkeyalg = pubkeyalgs;     /* see xt_sslpin.h */
    char *colon, *hex;
    int alg_len, pk_len, i;
    __u8 *pk, *pk_max;
    __u8 ms, ls;

    /* find pubkeyalg */
    colon = strchr(optarg, ':');
    if (!colon) {
        return false;
    }

    if (!(alg_len = colon - optarg)) {
        return false;
    }

    for (i = 0; i < SSLPIN_PUBLIC_KEY_ALGS_CNT; i++, pubkeyalg++) {
        if ((!strncmp(optarg, pubkeyalg->name, alg_len)) && (!pubkeyalg->name[alg_len])) {
            break;
        }
    }

    /* unknown algorithm */
    if (i == SSLPIN_PUBLIC_KEY_ALGS_CNT) {
        return false;
    }

    mtruleinfo->pk_alg = *pubkeyalg;

    /* parse pubkey hex string to bytes */
    hex = colon + 1;
    pk = mtruleinfo->pk;
    pk_max = pk + sizeof(mtruleinfo->pk);
    while (*hex) {
        if ((!hex[1]) || (pk == pk_max)) {
            return false;
        }

        ms = hexc2int(hex[0]);
        ls = hexc2int(hex[1]);
        if ((ms > 15) || (ls > 15)) {
            return false;
        }

        *pk++ = (ms << 4) | ls;
        hex += 2;
    }

    pk_len = pk - mtruleinfo->pk;
    if (pk_len < SSLPIN_MIN_PUBLIC_KEY_BYTELEN) {
        return false;
    }

    mtruleinfo->pk_len = pk_len;
    return true;
}


/* xtables_register_match() module init callback */         /* not needed */
/*
    static void sslpin_mt_init(struct xt_entry_match *match)
    {
    }
*/


/* invoked by iptables -m sslpin -h */
static void sslpin_mt_help(void)
{
    printf(
        "sslpin match options:\n"
        "[!] --pubkey\t<pubkey-alg>:<pubkey-hex>\n"
        "\t\t\t\tSSL/TLS Certificate Public Key specification\n"
        "\t\t\t\tpubkey-alg: either \"rsa\", \"ec\" or \"dsa\"\n"
        "    --debug\t\t\tverbose mode (see kernel log)\n"
        "\n"
        );
}


/* parse options */
static int sslpin_mt_parse(int c, char **argv, int invert, unsigned int *flags, const void *entry,
            struct xt_entry_match **match)
{
    struct sslpin_mtruleinfo *mtruleinfo = (struct sslpin_mtruleinfo*)(*match)->data;

    switch (c) {
        case 'p':
            if (*flags) {
                xtables_error(PARAMETER_PROBLEM, "sslpin: --pubkey can only be specified once");
            }
            if (!parse_pubkey_opt(mtruleinfo, optarg)) {
                xtables_error(PARAMETER_PROBLEM, "sslpin: unable to parse --pubkey argument");
            }
            if (invert) {
                mtruleinfo->flags |= SSLPIN_RULE_FLAG_INVERT;
            }
            *flags = 1;     /* pubkey has been set, see sslpin_mt_check() */
            break;
        case 'd':
            mtruleinfo->flags |= SSLPIN_RULE_FLAG_DEBUG;
            break;
        default:
            return false;
    }

    return true;
}


/* check options after parsing */
static void sslpin_mt_check(unsigned int flags)
{
    if (flags == 0) {
        xtables_error(PARAMETER_PROBLEM, "sslpin: must specify --pubkey");
    }
}


/* invoked for iptables --list;  print options in human-friendly format */
static void sslpin_mt_print(const void *entry, const struct xt_entry_match *match, int numeric)
{
    struct sslpin_mtruleinfo *mtruleinfo = (struct sslpin_mtruleinfo*)(match->data);

    printf(" sslpin:");

    if (mtruleinfo->flags & SSLPIN_RULE_FLAG_DEBUG) {
        printf(" debug");
    }
    if (mtruleinfo->flags & SSLPIN_RULE_FLAG_INVERT) {
        printf(" !");
    }
    printf(" alg: ");
    printf("%s", mtruleinfo->pk_alg.name);
    printf(" pk: (hex)");
}


/* invoked for iptables-save and iptables --list-rules;  print options in exact format */
static void sslpin_mt_save(const void *entry, const struct xt_entry_match *match)
{
    struct sslpin_mtruleinfo *mtruleinfo = (struct sslpin_mtruleinfo*)(match->data);

    if (mtruleinfo->flags & SSLPIN_RULE_FLAG_DEBUG) {
        printf(" --debug");
    }
    if (mtruleinfo->flags & SSLPIN_RULE_FLAG_INVERT) {
        printf(" !");
    }
    printf(" --pubkey ");
    printf("%s", mtruleinfo->pk_alg.name);
    printf(":");

    printhex(mtruleinfo->pk, mtruleinfo->pk_len);
}


/* xtables_register_match() module info */
static struct xtables_match sslpin_mt_reg = {
    .name           = "sslpin",
    .family         = NFPROTO_IPV4,
    .version        = XTABLES_VERSION,
    .revision       = 0,
    .size           = SSLPIN_MTRULEINFO_KERN_SIZE,
    .userspacesize  = SSLPIN_MTRULEINFO_USER_SIZE,
    .help           = sslpin_mt_help,
    .parse          = sslpin_mt_parse,
    .final_check    = sslpin_mt_check,
    .print          = sslpin_mt_print,
    .save           = sslpin_mt_save,
    .extra_opts     = sslpin_mt_opts,
/*    .init           = sslpin_mt_init, */      /* not needed */
};


/* init function (module loaded by iptables) */
void _init(void)
{
    xtables_register_match(&sslpin_mt_reg);
}

