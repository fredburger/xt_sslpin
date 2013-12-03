/*
 * xt_sslpin.c
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/highmem.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <net/netfilter/nf_conntrack_ecache.h>

#include "xt_sslpin.h"
#include "hexutils.h"
#include "ipfragment.h"
#include "xt_globals.h"
#include "xt_sslpin_connstate.h"
#include "xt_sslpin_sslparser.h"


MODULE_AUTHOR       ( "fredburger (github.com/fredburger) ");
MODULE_DESCRIPTION  ( "xtables: match SSL/TLS certificate public key" );
MODULE_LICENSE      ( "GPL" );
MODULE_ALIAS        ( "ipt_sslpin" );


/* forward decls */
static struct nf_ct_event_notifier  sslpin_conntrack_notifier;
static struct xt_match              sslpin_mt_reg               __read_mostly;


/* module init function */
static int __init sslpin_mt_init(void)
{
    int ret;

    pr_info("xt_sslpin 1.0 (SSL/TLS pinning)\n");

    if (!sslpin_connstate_cache_init()) {
        pr_err("xt_sslpin: could not allocate sslpin_connstate cache\n");
        return -ENOMEM;
    }

    ret = nf_conntrack_register_notifier(&init_net, &sslpin_conntrack_notifier);
    if (ret < 0) {
        pr_err("xt_sslpin: could not register conntrack event listener\n");
        sslpin_connstate_cache_destroy();
        return ret;
    }

    ret = xt_register_match(&sslpin_mt_reg);
    if (ret != 0) {
        pr_err("xt_sslpin: error registering sslpin match\n");
        nf_conntrack_unregister_notifier(&init_net, &sslpin_conntrack_notifier);
        sslpin_connstate_cache_destroy();
    }

    return ret;
}


/* module exit function */
static void __exit sslpin_mt_exit(void)
{
    pr_info("xt_sslpin 1.0 unload\n");
    xt_unregister_match(&sslpin_mt_reg);
    nf_conntrack_unregister_notifier(&init_net, &sslpin_conntrack_notifier);
    sslpin_connstate_cache_destroy();
}


/* module instance/rule destroy
 * when a rule is added or removed, sslpin_mt_check() will first be called once for each remaining rule,
 * then sslpin_mt_destroy() will be called */
static void sslpin_mt_destroy(const struct xt_mtdtor_param *par)
{
    spin_lock_bh(&sslpin_mt_lock);
    sslpin_mt_checked_after_destroy = false;
    spin_unlock_bh(&sslpin_mt_lock);
}


/* validate options passed in from usermode */
static int sslpin_mt_check(const struct xt_mtchk_param *par)
{
    struct sslpin_mtruleinfo *mtruleinfo = par->matchinfo;

    /* sanity check input options */
    if (unlikely(mtruleinfo->cn_len > SSLPIN_MAX_COMMON_NAME_UTF8_BYTELEN)) {
        return EINVAL;
    }

    if (unlikely(mtruleinfo->cn[SSLPIN_MAX_COMMON_NAME_UTF8_BYTELEN])) {
        return EINVAL;
    }

    if (unlikely((!mtruleinfo->pk_alg.name[0]) || mtruleinfo->pk_alg.name[sizeof(mtruleinfo->pk_alg.name) - 1])) {
        return EINVAL;
    }

    if (unlikely(mtruleinfo->pk_alg.oid_asn1[0] < 3)) {
        return EINVAL;
    }

    if (unlikely(mtruleinfo->pk_alg.oid_asn1[0] > sizeof(mtruleinfo->pk_alg.oid_asn1) - 1)) {
        return EINVAL;
    }

    if (unlikely((mtruleinfo->pk_len < SSLPIN_MIN_PUBLIC_KEY_BYTELEN)
        || (mtruleinfo->pk_len > SSLPIN_MAX_PUBLIC_KEY_BYTELEN)))
    {
        return EINVAL;
    }

    /* update sslpin_mt_has_debug_rules */
    spin_lock_bh(&sslpin_mt_lock);
    if (likely(sslpin_mt_checked_after_destroy)) {
        if (unlikely(sslpin_debug_enabled(mtruleinfo))) {
            sslpin_mt_has_debug_rules = true;
        }
    } else {
        sslpin_mt_has_debug_rules = mtruleinfo->flags & SSLPIN_RULE_FLAG_DEBUG;
        sslpin_mt_checked_after_destroy = true;
    }
    spin_unlock_bh(&sslpin_mt_lock);

    return 0;
}


/* compare rule specification against parsed certificate / public key */
static bool sslpin_match_certificate(const struct sslpin_mtruleinfo * const mtruleinfo,
            const struct sslparser_ctx * const parser_ctx)
{
    const bool invert = mtruleinfo->flags & SSLPIN_RULE_FLAG_INVERT;

    if (unlikely(!sslpin_pubkeyalg_equalnames(&mtruleinfo->pk_alg, parser_ctx->results.pubkey_alg))) {
        return invert;
    }

    if (unlikely((!mtruleinfo->pk_len) || (mtruleinfo->pk_len != parser_ctx->results.pubkey_len))) {
        return invert;
    }

    if (unlikely(memcmp(mtruleinfo->pk, parser_ctx->results.pubkey, mtruleinfo->pk_len))) {
        return invert;
    }

    if (unlikely(mtruleinfo->cn_len)) {
        if (unlikely(mtruleinfo->cn_len != parser_ctx->results.cn_len)) {
            return invert;
        }

        if (unlikely(memcmp(mtruleinfo->cn, parser_ctx->results.cn, mtruleinfo->cn_len))) {
            return invert;
        }
    }

    return !invert;
}


/*
 * main packet matching function
 *
 * Per connection, the incoming handshake data is parsed once across all -m sslpin iptables rules;
 * upon receiving the SSL/TLS handshake ChangeCipherSpec message, the parsed certificate is checked by all rules.
 *
 * After this, the connection is marked as "finished", and xt_sslpin will not do any further checking.
 * (Re-handshaking will not be checked in order to incur minimal overhead, and as the server has already proved
 * its identity).
 *
 * Up until the ChangeCipherSpec message is received, xt_sslpin will drop out-of-order TCP segments to
 * parse the data linearly without buffering. Conntrack takes care of IP fragment reassembly up-front, but packets
 * can still have non-linear memory layout; see skb_is_nonlinear().
 *
 * If SYN is received on a time-wait state conn/flow, conntrack will destroy the old cf_conn
 * and create a new cf_conn. Thus, our per-conn state transitions are simply new->open->destroyed (no reopen).
 *
 * Todo:
 *   - ECParameters/namedCurve pinning in addition to current alg+pubkey pinning
 *   - Optional buffering for reordered TCP segments during handshake (no RTT penalty / overhead)
 *   - TCP Fast Open (TFO) support (+ protect against spoofed TFO SYN/ACKs when has not been requested,
 *     but this should be handled by checking sequence numbers (SYN/ACK data accounted for in the following
 *     packets))
 *   - Supported TCP Options verification to ensure xp_sslpin is always in sync. with the TCP stack.
 *     Could pass all packets through an internal instance of the TCP stack before parsing payload data.
 *   - IPv6 support
 *   - Consider using the Linux ASN.1 compiler/decoder
 */
static bool sslpin_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
    const struct sslpin_mtruleinfo * const mtruleinfo = par->matchinfo;
    const bool debug_enabled = sslpin_debug_enabled(mtruleinfo);
    const struct iphdr *ip;
    const struct tcphdr *tcp;
    struct sslpin_connstate *state;
    __u32 tcp_seq, data_len, nonpaged_len, i, num_frags;
    __u8 *data;
    skb_frag_t *frag;
    int frag_size;
    sslparser_res_t res;
    bool matched;

    /* check that conntrack flow binding is provided */
    if (unlikely(!skb->nfct)) {
        par->hotdrop = true;
        if (unlikely(debug_enabled)) {
            pr_err("xt_sslpin: no conntrack data (conntrack not enabled?) - dropping packet!\n");
        }
        return false;
    }

    /* check connection state - only handle established replies */
    if (unlikely(skb->nfctinfo != IP_CT_ESTABLISHED_REPLY)) {
        return false;
    }

    /* acquire module-wide lock */
    spin_lock_bh(&sslpin_mt_lock);

    /* lookup sslpin_connstate for connection */
    state = sslpin_connstate_find_or_init((struct nf_conn *)skb->nfct);

    if (unlikely(!state)) {
        spin_unlock_bh(&sslpin_mt_lock);
        par->hotdrop = true;
        if (unlikely(debug_enabled)) {
            pr_err("xt_sslpin: unable to allocate sslpin_connstate - dropping packet!\n");
        }
        return false;
    }

    /* check if this connection has been marked as FINISHED (certificate has been checked
     * or connection was already established when xt_sslpin was loaded (SYN/ACK not seen) */
    if (likely(state->state == SSLPIN_CONNSTATE_FINISHED)) {
        spin_unlock_bh(&sslpin_mt_lock);
        return false;
    }

    /* check if this connection has been marked as INVALID (e.g. invalid SSL/TLS/x509 data or parser error) */
    if (unlikely(state->state == SSLPIN_CONNSTATE_INVALID)) {
        spin_unlock_bh(&sslpin_mt_lock);
        par->hotdrop = true;
        return false;
    }

    /* get IP header */
    ip = ip_hdr(skb);
    if (unlikely(!ip)) {
        spin_unlock_bh(&sslpin_mt_lock);
        par->hotdrop = true;
        if (unlikely(debug_enabled)) {
            pr_err("xt_sslpin: no IP header - dropping packet!\n");
        }
        return false;
    }

    /* require IPv4 */
    if (unlikely(ip->version != 4)) {
        spin_unlock_bh(&sslpin_mt_lock);
        par->hotdrop = true;
        if (unlikely(debug_enabled)) {
            pr_err("xt_sslpin: IPv6 not yet supported\n");
        }
        return false;
    }

    /* check protocol TCP */
    if (unlikely(ip->protocol != IPPROTO_TCP)) {
        spin_unlock_bh(&sslpin_mt_lock);
        par->hotdrop = true;
        if (unlikely(debug_enabled)) {
            pr_err("xt_sslpin: unknown IP protocol %d - dropping packet!\n", ip->protocol);
        }
        return false;
    }

    /* check for fragment offset > 0 or "more fragments" bit set */
    if (unlikely(is_ip_fragment(par->fragoff | ip->frag_off))) {
        spin_unlock_bh(&sslpin_mt_lock);
        par->hotdrop = true;
        if (unlikely(debug_enabled)) {
            pr_err("xt_sslpin: IP fragment seen (conntrack not enabled?) - dropping packet!\n");
        }
        return false;
    }

    /* get TCP header */
    tcp = (struct tcphdr*)((__u32*)ip + ip->ihl);
    tcp_seq = ntohl(tcp->seq);
    data_len = ntohs(ip->tot_len) - (tcp->doff << 2) - (ip->ihl << 2);

    /* check for SYN/ACK on new connections */
    if (unlikely(tcp->syn)) {
        if (unlikely(data_len)) {
            spin_unlock_bh(&sslpin_mt_lock);
            par->hotdrop = true;
            if (unlikely(debug_enabled)) {
                pr_err("xt_sslpin: received SYN/ACK packet with data!? dropping packet"
                    " (TCP Fast Open not current supported by xt_sslpin)\n");
            }
            return false;
        }

        if (unlikely(!tcp->ack)) {
            state->state = SSLPIN_CONNSTATE_INVALID;
            spin_unlock_bh(&sslpin_mt_lock);
            par->hotdrop = true;
            if (unlikely(debug_enabled)) {
                pr_err("xt_sslpin: received SYN packet (without ACK)"
                    " - dropping packet and marking connection as invalid\n");
            }
            return false;
        }

        if (unlikely(state->state >= SSLPIN_CONNSTATE_GOT_DATA)) {
            state->state = SSLPIN_CONNSTATE_INVALID;
            if (unlikely(state->parser_ctx)) {
                sslpin_connstate_unbind_parser(state);
            }
            spin_unlock_bh(&sslpin_mt_lock);
            par->hotdrop = true;
            if (unlikely(debug_enabled)) {
                pr_err("xt_sslpin: received SYN/ACK for connection that has received data"
                    " - dropping packet and marking connection as invalid\n");
            }
            return false;
        }

        if (unlikely(debug_enabled && (state->state == SSLPIN_CONNSTATE_GOT_SYNACK))
            && (tcp_seq != state->last_seq))
        {
            pr_info("xt_sslpin: received duplicate SYN/ACK with different seq\n");
        }

        /* valid SYN/ACK connection establishment */
        state->state = SSLPIN_CONNSTATE_GOT_SYNACK;
        state->last_seq = tcp_seq;
        state->last_len = 1;        /* SYN phantom byte */
        spin_unlock_bh(&sslpin_mt_lock);
        return false;
    }

    /* check for connections without SYN/ACK seen (already established when xt_sslpin was loaded) */
    if (unlikely(state->state < SSLPIN_CONNSTATE_GOT_SYNACK)) {
        state->state = SSLPIN_CONNSTATE_FINISHED;
        spin_unlock_bh(&sslpin_mt_lock);
        if (unlikely(debug_enabled)) {
            pr_err("xt_sslpin: SYN/ACK not seen for connection (already established when xt_sslpin was loaded)"
                " - ignoring connection\n");
        }
        return false;
    }

    /* handle duplicated packets (also when xt_sslpin is invoked once per rule with the same packet) */
    if (likely((tcp_seq == state->last_seq) && (ip->id == state->last_ipid) && (data_len == state->last_len))) {
        if (unlikely((state->state != SSLPIN_CONNSTATE_CHECK_RULES) || (!state->parser_ctx))) {
            /* packet data was already parsed, and a certificate was not seen */
            spin_unlock_bh(&sslpin_mt_lock);
            return false;
        }
        /* fall through to certificate handling */
    } else {
        /* if previous state is SSLPIN_CONNSTATE_CHECK_RULES, transition to SSLPIN_CONNSTATE_FINISHED */
        if (unlikely(state->state == SSLPIN_CONNSTATE_CHECK_RULES)) {
            if (likely(state->parser_ctx)) {
                sslpin_connstate_unbind_parser(state);
            }
            state->state = SSLPIN_CONNSTATE_FINISHED;
            spin_unlock_bh(&sslpin_mt_lock);
            return false;
        }

        /* new packet - check TCP sequence number - drop out-of-order packets */
        if (unlikely(tcp_seq != state->last_seq + state->last_len)) {
            if (unlikely(debug_enabled)) {
                pr_err("xt_sslpin: out-of-order TCP segment (expecting seq 0x%08x, packet has 0x%08x)"
                    " - dropping packet\n",
                    state->last_seq + state->last_len,
                    tcp_seq);
            }
            spin_unlock_bh(&sslpin_mt_lock);
            par->hotdrop = true;
            return false;
        }

        /* sanity check TCP segment length */
        if (unlikely(data_len > 1 << 30)) {
            spin_unlock_bh(&sslpin_mt_lock);
            par->hotdrop = true;
            if (unlikely(debug_enabled)) {
                pr_err("xt_sslpin: data_len == %d - dropping packet!\n", data_len);
            }
            return false;
        }

        /* update seq */
        state->last_seq = tcp_seq;
        state->last_len = data_len;
        state->last_ipid = ip->id;

        /* exit for empty packets */
        if (unlikely(!data_len)) {
            spin_unlock_bh(&sslpin_mt_lock);
            return false;
        }

        /* parse new data */
        if (unlikely(state->state < SSLPIN_CONNSTATE_GOT_DATA)) {
            state->state = SSLPIN_CONNSTATE_GOT_DATA;
        }

        /* allocate parser ctx for conn */
        if (unlikely(!state->parser_ctx)) {
            if (unlikely(!sslpin_connstate_bind_parser(state, sslpin_mt_has_debug_rules))) {
                state->state = SSLPIN_CONNSTATE_INVALID;
                spin_unlock_bh(&sslpin_mt_lock);
                par->hotdrop = true;
                if (unlikely(debug_enabled)) {
                    pr_err("xt_sslpin: unable to allocate parser context for connection"
                        " - dropping packet and marking connection as invalid\n");
                }
                return false;
            }
        }

        /* non-paged data */
        nonpaged_len = skb->len - skb->data_len - (tcp->doff << 2) - (ip->ihl << 2);
        data = (__u8 *)tcp + (tcp->doff << 2);
        res = sslparser(state->parser_ctx, data, nonpaged_len);

        if (unlikely((res == SSLPARSER_RES_CONTINUE) && skb_is_nonlinear(skb))) {
            /* paged data */
            num_frags = skb_shinfo(skb)->nr_frags;
            for (i = 0; i < num_frags; i++) {
                frag = &skb_shinfo(skb)->frags[i];
                frag_size = skb_frag_size(frag);
                if (unlikely(frag_size <= 0)) {
                    continue;
                }

                data = kmap_atomic(skb_frag_page(frag));
                res = sslparser(state->parser_ctx, data + frag->page_offset, frag_size);
                kunmap_atomic(data);

                if (unlikely(res != SSLPARSER_RES_CONTINUE)) {
                    break;
                }
            }
        }

        if (likely(res == SSLPARSER_RES_CONTINUE)) {
            spin_unlock_bh(&sslpin_mt_lock);
            return false;
        }

        if (unlikely(res != SSLPARSER_RES_FINISHED)) {
            if (likely(state->parser_ctx)) {
                sslpin_connstate_unbind_parser(state);
            }
            state->state = SSLPIN_CONNSTATE_INVALID;
            spin_unlock_bh(&sslpin_mt_lock);
            par->hotdrop = true;
            if (unlikely(debug_enabled)) {
                pr_warn("xt_sslpin: invalid SSL/TLS/X509 data received"
                    " - dropping packet and marking connection as invalid\n");
            }
            return false;
        }

        /* parser returned certificate - transition connection to SSLPIN_CONNSTATE_CHECK_RULES state */
        state->state = SSLPIN_CONNSTATE_CHECK_RULES;
    }


    /* check certificate public key */
    matched = likely(state->parser_ctx) && sslpin_match_certificate(mtruleinfo, state->parser_ctx);

    if (unlikely(debug_enabled)) {
        pr_info("xt_sslpin: rule %smatched (cn = \"%s\")\n", matched ? "" : "not ",
            state->parser_ctx ? (char*)&state->parser_ctx->results.cn : NULL);
    }

    spin_unlock_bh(&sslpin_mt_lock);
    return matched;
}


/* conntrack event listener (remove closed conns) */
static int sslpin_conntrack_event(unsigned int events, struct nf_ct_event *item)
{
    struct sslpin_connstate *state;

    if (likely(((events & (1 << IPCT_DESTROY)) == 0) || (!item))) {
        return NOTIFY_DONE;
    }

    // todo: check for IPv4 TCP yes/no without acquiring spinlock or traversing the rb-tree

    spin_lock_bh(&sslpin_mt_lock);

    state = sslpin_connstate_find(item->ct, NULL);
    if (likely(!state)) {
        spin_unlock_bh(&sslpin_mt_lock);
        return NOTIFY_DONE;
    }

    sslpin_connstate_remove(state);
    if (unlikely(sslpin_mt_has_debug_rules)) {
        sslpin_connstate_debug_count();
    }

    spin_unlock_bh(&sslpin_mt_lock);
    return NOTIFY_DONE;
}


/* conntrack event listener registration data */
static struct nf_ct_event_notifier sslpin_conntrack_notifier = {
    .fcn = sslpin_conntrack_event,
};


/* registry information for the match checking functions */
static struct xt_match  sslpin_mt_reg  __read_mostly = {
    .name = "sslpin",
    .revision = 0,
    .family = NFPROTO_IPV4,
    .match = sslpin_mt,
    .checkentry = sslpin_mt_check,
    .destroy = sslpin_mt_destroy,
    .matchsize = XT_ALIGN(sizeof(struct sslpin_mtruleinfo)),
    .me = THIS_MODULE,
};


/* bind module init & exit */
module_init(sslpin_mt_init);
module_exit(sslpin_mt_exit);
