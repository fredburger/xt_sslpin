/*
 * xt_sslpin_connstate.h
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

#ifndef _LINUX_NETFILTER_XT_SSLPIN_CONNSTATE_H
#define _LINUX_NETFILTER_XT_SSLPIN_CONNSTATE_H


#include "xt_sslpin_sslparser.h"


typedef enum {
    SSLPIN_CONNSTATE_NEW,
    SSLPIN_CONNSTATE_INVALID,
    SSLPIN_CONNSTATE_GOT_SYNACK,
    SSLPIN_CONNSTATE_GOT_DATA,
    SSLPIN_CONNSTATE_CHECK_RULES,
    SSLPIN_CONNSTATE_FINISHED
} sslpin_connstate_state_t;

struct sslpin_connstate {
    struct rb_node              node;
    struct nf_conn              *nfct;
    sslpin_connstate_state_t    state;
    __u32                       last_seq;
    __u32                       last_len;
    __u16                       last_ipid;
    struct sslparser_ctx        *parser_ctx;
};


/* per-connection state tracking table */
static struct rb_root       sslpin_connstate_root       = RB_ROOT;
static struct kmem_cache    *sslpin_connstate_cache     __read_mostly;
static struct kmem_cache    *sslpin_parserctx_cache     __read_mostly;
static __u32                sslpin_connstate_count      = 0;
static __u32                sslpin_parserctx_count      = 0;


/* print n.o. tracked connections */
static void sslpin_connstate_debug_count(void)
{
    pr_info("xt_sslpin: %d connection%s (%d actively monitored)\n", sslpin_connstate_count,
        (sslpin_connstate_count != 1) ? "s" : "",
        sslpin_parserctx_count);
}


/* create parser_ctx for conn */
static struct sslparser_ctx * sslpin_connstate_bind_parser(struct sslpin_connstate *state, const bool enable_debug)
{
    if (unlikely(state->parser_ctx)) {
        return state->parser_ctx;
    }

    state->parser_ctx = kmem_cache_zalloc(sslpin_parserctx_cache, GFP_ATOMIC);
    if (likely(state->parser_ctx)) {
        state->parser_ctx->debug = enable_debug;
        sslpin_parserctx_count++;
        if (unlikely(sslpin_mt_has_debug_rules)) {
            sslpin_connstate_debug_count();
        }
    }
    return state->parser_ctx;
}

/* destroy parser_ctx for conn */
static void sslpin_connstate_unbind_parser(struct sslpin_connstate *state)
{
    if (likely(state->parser_ctx)) {
        kmem_cache_free(sslpin_parserctx_cache, state->parser_ctx);
        state->parser_ctx = NULL;
        sslpin_parserctx_count--;
        if (unlikely(sslpin_mt_has_debug_rules)) {
            sslpin_connstate_debug_count();
        }
    }
}

/* remove a conn from the tracking table */
static void sslpin_connstate_remove(struct sslpin_connstate *state)
{
    sslpin_connstate_unbind_parser(state);
    rb_erase(&state->node, &sslpin_connstate_root);
    kmem_cache_free(sslpin_connstate_cache, state);
    sslpin_connstate_count--;
}


/* init conn tracking table */
static bool sslpin_connstate_cache_init(void)
{
    sslpin_connstate_cache = kmem_cache_create("xt_sslpin_connstate", sizeof(struct sslpin_connstate), 0, 0, NULL);
    if (unlikely(!sslpin_connstate_cache)) {
        return false;
    }

    sslpin_parserctx_cache = kmem_cache_create("xt_sslpin_parser", sizeof(struct sslparser_ctx), 0, 0, NULL);
    if (unlikely(!sslpin_parserctx_cache)) {
        kmem_cache_destroy(sslpin_connstate_cache);
        return false;
    }

    return true;
}


/* destroy conn tracking table */
static void sslpin_connstate_cache_destroy(void)
{
    struct rb_node *node;
    struct sslpin_connstate *state;

    if (unlikely(!sslpin_connstate_cache)) {
        return;
    }

    node = rb_first(&sslpin_connstate_root);
    while (node) {
        state = rb_entry(node, struct sslpin_connstate, node);
        node = rb_next(&state->node);
        sslpin_connstate_remove(state);
    }

    if (likely(sslpin_parserctx_cache)) {
        kmem_cache_destroy(sslpin_parserctx_cache);
    }

    kmem_cache_destroy(sslpin_connstate_cache);
}


/* find a conn in the tracking table, or return NULL */
static struct sslpin_connstate * sslpin_connstate_find(struct nf_conn *nfct,
            struct sslpin_connstate **insertion_point_out)
{
    struct rb_node *node = sslpin_connstate_root.rb_node;
    struct sslpin_connstate *state = NULL;
    struct nf_conn *node_nfct;

    while (node) {
        state = rb_entry(node, struct sslpin_connstate, node);
        node_nfct = state->nfct;

        if (nfct < node_nfct) {
            node = node->rb_left;
        } else if (nfct > node_nfct) {
            node = node->rb_right;
        } else {
            return state;
        }
    }

    if (likely(insertion_point_out)) {
        *insertion_point_out = state;
    }

    return NULL;
}


/* find a conn in the tracking table, or add it */
static struct sslpin_connstate * sslpin_connstate_find_or_init(struct nf_conn *nfct)
{
    struct sslpin_connstate *state;
    struct sslpin_connstate *insertion_point;
    struct rb_node *insertion_node;
    struct rb_node **insertion_branch;

    if (likely(state = sslpin_connstate_find(nfct, &insertion_point))) {
        return state;
    }

    state = kmem_cache_zalloc(sslpin_connstate_cache, GFP_ATOMIC);
    if (unlikely(!state)) {
        return NULL;
    }

    state->nfct = nfct;

    if (likely(insertion_point)) {
        insertion_node = &insertion_point->node;
        if (nfct < insertion_point->nfct) {
            insertion_branch = &insertion_node->rb_left;
        } else {
            insertion_branch = &insertion_node->rb_right;
        }
    } else {
        insertion_node = NULL;
        insertion_branch = &sslpin_connstate_root.rb_node;
    }

    rb_link_node(&state->node, insertion_node, insertion_branch);
    rb_insert_color(&state->node, &sslpin_connstate_root);

    sslpin_connstate_count++;

    if (unlikely(sslpin_mt_has_debug_rules)) {
        sslpin_connstate_debug_count();
    }

    return state;
}


#endif /* _LINUX_NETFILTER_XT_SSLPIN_CONNSTATE_H */
