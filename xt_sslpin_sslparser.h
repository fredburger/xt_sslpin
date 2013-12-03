/*
 * xt_sslpin_sslparser.h
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

#ifndef _LINUX_NETFILTER_XT_SSLPIN_SSLPARSER_H
#define _LINUX_NETFILTER_XT_SSLPIN_SSLPARSER_H


#include "ssl_tls.h"


typedef enum {
    SSLPARSER_RES_NONE,
    SSLPARSER_RES_CONTINUE,
    SSLPARSER_RES_INVALID,
    SSLPARSER_RES_FINISHED
} sslparser_res_t;


#define SSLPARSER_MAX_COMMON_NAME_LEN               SSLPIN_MAX_COMMON_NAME_UTF8_BYTELEN
#define SSLPARSER_MAX_PUBLIC_KEY_BYTELEN            SSLPIN_MAX_PUBLIC_KEY_BYTELEN
#define SSLPARSER_MAX_PUBLIC_KEY_ALG_OID_BYTELEN    SSLPIN_MAX_PUBLIC_KEY_ALG_OID_BYTELEN

#define SSLPARSER_STATE_INVALID                     (__u8)-1
#define SSLPARSER_STATE_FINISHED                    (__u8)-2


struct sslparser_ctx {
    /* Parser state variables */
    __u8        state;
    bool        debug : 1;
    __u8        tls_ver_minor : 4;
    bool        cert_msg_seen : 1;
    __u16       state_remain;
    __u16       a, b, c;
    __u8        record_type;
    __u8        msg_type;
    __u16       record_remain;
    __u16       msg_remain;
    __u16       firstcert_remain;

    /* Parser results */
    struct {
        /* Common Name (utf-8 + zero) */
        __u16                           cn_len;
        char                            cn[SSLPARSER_MAX_COMMON_NAME_LEN + 1];

        /* Public Key */
        __u16                           pubkey_len;
        __u8                            pubkey[SSLPARSER_MAX_PUBLIC_KEY_BYTELEN];

        /* Public Key Algorithm oid with length in [0] */
        __u8                            pubkey_alg_oid[SSLPIN_MAX_PUBLIC_KEY_ALG_OID_BYTELEN];

        /* Public Key Algorithm - resolved algorithm name or NULL */
        const struct sslpin_pubkeyalg   *pubkey_alg;
    } results;
};


#pragma push_macro("ul")
#pragma push_macro("l")
#pragma push_macro("invalid")
#pragma push_macro("finished")
#pragma push_macro("need_more_data")
#pragma push_macro("debug")
#pragma push_macro("go_state")
#pragma push_macro("data_remain")
#pragma push_macro("bind_state_remain")
#pragma push_macro("state_remain")
#pragma push_macro("step_proto")
#pragma push_macro("_step_state")
#pragma push_macro("step_state")
#pragma push_macro("step_state_to")


#define ul(x)       unlikely(x)
#define l(x)        likely(x)

#define invalid(fmt, ...)                                                                                           \
    if (ul(state->debug)) {                                                                                         \
        pr_err("xt_sslpin: sslparser: " fmt, ##__VA_ARGS__);                                                        \
    }                                                                                                               \
    state->state = SSLPARSER_STATE_INVALID;                                                                         \
    return SSLPARSER_RES_INVALID;

#define finished()                                                                                                  \
    state->state = SSLPARSER_STATE_FINISHED;                                                                        \
    return SSLPARSER_RES_FINISHED;

#define need_more_data()                                                                                            \
    state->state = statev;                                                                                          \
    return SSLPARSER_RES_CONTINUE;

#define debug(fmt, ...)                                                                                             \
    if (ul(state->debug)) {                                                                                         \
        pr_info("xt_sslpin: sslparser: " fmt, ##__VA_ARGS__);                                                       \
    }

#define go_state(new_state, label)                                                                                  \
    statev = new_state;                                                                                             \
    goto label;

#define data_remain()                                                                                               \
    (data_end - data)

#define bind_state_remain(remain)                                                                                   \
    state->state_remain = remain;                                                                                   \
    state_end = data + remain;

#define state_remain()                                                                                              \
    (state_end - data)

#define step_proto()                                                                                                \
    if (ul(++data == data_end)) {                                                                                   \
        state->state = ++statev;                                                                                    \
        state->state_remain = state_remain();                                                                       \
        need_more_data();                                                                                           \
    }                                                                                                               \
    statev++;

#define _step_state()                                                                                               \
    if (ul(++data > state_end)) {                                                                                   \
        invalid("expected more data");                                                                              \
    }

#define step_state()                                                                                                \
    _step_state();                                                                                                  \
    if (ul(data == data_end)) {                                                                                     \
        state->state = ++statev;                                                                                    \
        state->state_remain = state_remain();                                                                       \
        need_more_data();                                                                                           \
    }                                                                                                               \
    statev++;

#define step_state_to(new_state, label)                                                                             \
    _step_state();                                                                                                  \
    if (ul(data == data_end)) {                                                                                     \
        state->state = statev = new_state;                                                                          \
        state->state_remain = state_remain();                                                                       \
        need_more_data();                                                                                           \
    }                                                                                                               \
    go_state(new_state, label);


static const struct sslpin_pubkeyalg *sslparser_lookup_pubkey_alg_oid(struct sslparser_ctx *state) {
    const struct sslpin_pubkeyalg *alg_end = pubkeyalgs + SSLPIN_PUBLIC_KEY_ALGS_CNT;
    const struct sslpin_pubkeyalg *alg;
    for (alg = pubkeyalgs; alg < alg_end; alg++) {
        if (l(alg->oid_asn1[0] == state->results.pubkey_alg_oid[0])) {
            if (l(!memcmp(alg->oid_asn1 + 1, state->results.pubkey_alg_oid + 1, alg->oid_asn1[0]))) {
                return alg;
            }
        }
    }
    return NULL;
}


static sslparser_res_t sslparser(struct sslparser_ctx * const state, const __u8 *data, const __u32 data_len)
{
    const __u8  version_bytes[]         = { 0xa0, 0x03, 0x02, 0x01, 0x02 };
    const __u8  cert_skiplist_types[]   = { 0x02, 0x30, 0x30, 0x30 };
    const __u8  rdn_attrtype_prefix[]   = { 0x06, 0x03, 0x55, 0x04 };
    const __u8 *const data_end          = data + data_len;
    const __u8 *state_end               = data + state->state_remain;
    __u8        statev                  = state->state;
    const char *str;

    if (ul(statev >= SSLPARSER_STATE_FINISHED)) {
        return l(statev == SSLPARSER_STATE_FINISHED) ? SSLPARSER_RES_FINISHED : SSLPARSER_RES_INVALID;
    }
    if (ul(!data_len)) {
        need_more_data();
    }

    switch (statev) {

state0_record_begin:
        /* SSL/TLS record: first byte: record type */
        case 0:
            state->record_type = *data;
            if (ul((state->record_type != SSL3_RT_HANDSHAKE) && (state->record_type != SSL3_RT_CHANGE_CIPHER_SPEC))) {
                invalid("invalid SSL/TLS record type %d; expected SSL3_RT_HANDSHAKE\n", state->record_type);
            }
            step_proto();

        /* bytes 1-2: SSL version (major/minor); see ssl_tls.h: SSL3_VERSION */
        case 1:
            if (ul(*data != 3)) {
                invalid("unknown SSL/TLS major version %d\n", *data);
            }
            step_proto();
        case 2:
            if (ul((*data) > 3)) {
                invalid("unknown SSL/TLS minor version %d\n", *data);
            }
            if (l(!state->tls_ver_minor)) {
                state->tls_ver_minor = *data + 1;
            } else if (ul(*data != state->tls_ver_minor - 1)) {
                invalid("records have different SSL/TLS minor versions\n");
            }
            step_proto();

        /* bytes 3-4: Record data length (excluding header) */
        case 3:
            state->record_remain = *data << 8;
            step_proto();
        case 4:
            state->record_remain |= *data;
            bind_state_remain(state->record_remain + 1);
            step_proto();

state5_message_begin:
        /* byte 5: message type: expect Handshake or ChangeCipherSpec */
        case 5:
            if (ul(!data_remain())) {
                need_more_data();
            }

            state->msg_type = *data;

            /* ChangeCipherSpec record? */
            if (ul(state->record_type == SSL3_RT_CHANGE_CIPHER_SPEC)) {
                if (ul((state->msg_type != 1) || (state_remain() != 1))) {
                    invalid("invalid ChangeCipherSpec record (len = %ld, ccs_proto = %d)\n",
                        (long)state_remain(), state->msg_type);
                }
                debug("ChangeCipherSpec record\n");
                finished();
            }

            /* Handshake record */
            if (ul(state_remain() < 4)) {
                invalid("handshake record len == %ld (minimum is 4)\n", (long)state_remain());
            }
            step_state();

        /* byte 6-8: Handshake message length */
        case 6:
            state->msg_remain = *data << 16;
            step_state();
        case 7:
            state->msg_remain |= *data << 8;
            step_state();
        case 8:
            state->msg_remain |= *data;

            str = sslpin_ssl_handshake_mt_to_string(state->msg_type);
            if (ul(!str)) {
                invalid("unknown handshake message type %d (len = %d)\n", state->msg_type, state->msg_remain);
            }

            debug("%s handshake message (len = %d)\n", str, state->msg_remain);
            if (ul(state->msg_remain > state_remain() - 1)) {
                invalid("message len %d > remaining record len %ld\n", state->msg_remain, (long)state_remain() - 1);
            }

            /* Certificate message? */
            if (ul(state->msg_type == SSL3_MT_CERTIFICATE)) {
                step_state_to(40, state40_parse_certificate_message);
            }

            step_state_to(20, state20_skip_message);


state20_skip_message:
        /* skip over message, then go to either state5_message_begin or state0_record_begin */
        case 20:
            if (ul(data_remain() <= state->msg_remain)) {
                state->msg_remain -= data_remain();
                state->state_remain = state_remain() - data_remain();
                need_more_data();
            }

            data += state->msg_remain;
            if (l(data < state_end)) {
                go_state(5, state5_message_begin);
            }

            /* no more messages in record */
            go_state(0, state0_record_begin);


state40_parse_certificate_message:
        /* Certificate message parsing */
        case 40:
            if (ul(state->msg_remain < 32)) {
                invalid("Certificate message len == %d\n", state->msg_remain);
            }
            if (ul(state->cert_msg_seen)) {
                invalid("more than one Certificate message\n");
            }

            state->cert_msg_seen = true;
            state->a = *data << 16;
            step_state();
        case 41:
            state->a |= *data << 8;
            step_state();
        case 42:
            state->a |= *data;
            state->msg_remain -= 3;
            if (ul(state->a != state->msg_remain)) {
                invalid("certificates data length %d vs. msg_remain %d\n", state->a, state->msg_remain - 3);
            }

            state->record_remain = state_remain() - state->msg_remain;
            bind_state_remain(state->msg_remain + 1);
            step_state();

        /* parse first certificate length (3 bytes) */
        case 43:
            state->firstcert_remain = *data << 16;
            step_state();
        case 44:
            state->firstcert_remain |= *data << 8;
            step_state();
        case 45:
            state->firstcert_remain |= *data;
            if (ul((state->firstcert_remain > state_remain() - 1) || (state->firstcert_remain < 32))) {
                invalid("first certificate data length: %d\n", state->firstcert_remain);
            }

            state->msg_remain = state_remain() - state->firstcert_remain;
            bind_state_remain(state->firstcert_remain + 1);
            step_state();

        /* parse ASN.1: |Certificate ::= SEQUENCE {|  bytes: 0x30 0x82 len len  - expect 2-byte len */
        case 46:
            if (*data != 0x30) {
                invalid("invalid Certificate SEQUENCE type tag\n");
            }
            step_state();
        case 47:
            if (*data != 0x82) {
                invalid("invalid Certificate SEQUENCE len byte count\n");
            }
            step_state();
        case 48:
            state->a = *data << 8;
            step_state();
        case 49:
            state->a |= *data;
            if (ul(state->a != state_remain() - 1)) {
                invalid("invalid Certificate SEQUENCE len\n");
            }
            step_state();

        /* parse ASN.1: |TBSCertificate ::= SEQUENCE {|  bytes: 0x30 0x82 len len  - expect 2-byte len */
        case 50:
            if (*data != 0x30) {
                invalid("invalid TBSCertificate SEQUENCE type tag\n");
            }
            step_state();
        case 51:
            if (*data != 0x82) {
                invalid("invalid TBSCertificate SEQUENCE len byte count\n");
            }
            step_state();
        case 52:
            state->a = *data << 8;
            step_state();
        case 53:
            state->a |= *data;
            if (ul(state->a > state_remain())) {
                invalid("invalid TBSCertificate SEQUENCE len\n");
            }
            step_state();

        /* parse ASN.1: |version   [0] Version DEFAULT v1|  hex: a0 03 02 01 02  - expect v3 (last byte 2) */
        case 54:
            state->a = 0;
            statev++;

state55_check_certificate_version:
        case 55:
            if (ul(*data != version_bytes[state->a])) {
                invalid("invalid TBSCertificate.Version\n");
            }
            if (l(++state->a < sizeof(version_bytes))) {
                step_state_to(55, state55_check_certificate_version);
            }
            step_state();

        /* skip over certificate fields: serialNumber, signature, issuer and validity */
        case 56:
            state->a = 0;
            statev++;

state57_skip_certificate_fields:
        /* certificate field skip: check field type */
        case 57:
            if (ul(*data != cert_skiplist_types[state->a])) {
                invalid("TBSCertificate field %d has invalid type\n", state->a + 1);
            }
            step_state();

        /* certificate field skip: get field length */
        case 58:
            state->b = *data;

            /* single-byte length */
            if (l(state->b < 0x80)) {
                /* state->b holds actual single-byte length */
                step_state_to(60, state60_check_certificate_multibyte_fieldlen);
            }

            /* multi-byte length */
            state->c = state->b & 0x7f;
            if (ul((!state->c) || (state->c > 2))) {
                invalid("TBSCertificate field %d has invalid length\n", state->a);
            }

            state->b = 0;
            step_state();

        /* certificate field skip: get multi-byte field length */
state59_get_certificate_multibyte_fieldlen:
        case 59:
            state->b = (state->b << 8) | *data;
            if (l(--state->c)) {
                step_state_to(59, state59_get_certificate_multibyte_fieldlen);
            }
            step_state();

state60_check_certificate_multibyte_fieldlen:
        /* certificate field skip: validate field length */
        case 60:
            /* state->b: field length */
            if (ul(state->b > 16384)) {
                invalid("TBSCertificate field %d has invalid length\n", state->a + 1);
            }
            statev++;

        /* certificate field skip: skip over field */
        case 61:
            if (ul(data_remain() <= state->b)) {
                state->b -= data_remain();
                state->state_remain = state_remain() - data_remain();
                need_more_data();
            }
            data += state->b;
            if (l(++state->a < sizeof(cert_skiplist_types))) {
                go_state(57, state57_skip_certificate_fields);
            }
            go_state(80, state80_find_common_name);


state80_find_common_name:
        /* parse ASN.1: |RDNSequence ::= SEQUENCE OF RelativeDistinguishedName|  - find id-at-commonName utf-8 string */
        case 80:
            if (ul(*data != 0x30)) {
                invalid("subject field has invalid type tag\n");
            }
            step_state();

        /* RDNSequence: get outer sequence length (multi-byte accepted) */
        case 81:
            state->b = *data;

            /* single-byte length */
            if (l(state->b < 0x80)) {
                /* state->b holds actual single-byte length */
                step_state_to(90, state90_check_rdnsequence_len);
            }

            /* multi-byte length */
            state->c = state->b & 0x7f;
            if (ul((!state->c) || (state->c > 2))) {
                invalid("subject field has invalid length\n");
            }

            state->b = 0;
            step_state();

        /* RDNSequence: get outer sequence multi-byte length */
state82_get_rdnsequence_len:
        case 82:
            state->b = (state->b << 8) | *data;
            if (l(--state->c)) {
                step_state_to(82, state82_get_rdnsequence_len);
            }
            step_state_to(90, state90_check_rdnsequence_len);

state90_check_rdnsequence_len:
        /* RDNSequence: validate outer sequence length stored in acc2 */
        case 90:
            if (ul((state->b > state_remain()) || (state->b > 512))) {
                invalid("subject field has invalid length\n");
            }

            /* state->rdnseq_remain = state->b; */
            state->firstcert_remain = state_remain() - state->b;
            bind_state_remain(state->b);
            statev++;

state91_rdnsequence_item_begin:
        /* RDNSequence: check if item is id-at-commonName, first check item/entry type tag */
        case 91:
            if (ul(*data != 0x31)) {
                invalid("subject item has invalid type tag\n");
            }
            step_state();

        /* RDNSequence: get outer item length (single-byte) */
        case 92:
            state->a = *data;
            if (ul((state->a > state_remain()) || (state->a >= 0x80)) || (state->a < 7)) {
                invalid("subject item has invalid length\n");
            }
            step_state();

        /* RDNSequence: get inner item type tag */
        case 93:
            if (ul(*data != 0x30)) {
                invalid("subject inner item has invalid type tag\n");
            }
            step_state();

        /* RDNSequence: check inner item length (single-byte) */
        case 94:
            if (ul(*data != state->a - 2)) {
                invalid("subject inner item has invalid length\n");
            }
            step_state();

        /* RDNSequence: check AttributeType prefix byte 06 03 55 04 */
        case 95:
            state->b = 0;
            statev++;

state96_compare_rdnsequence_item_prefix:
        case 96:
            if (ul(*data != rdn_attrtype_prefix[state->b])) {
                state->a += sizeof(rdn_attrtype_prefix) - state->b;
                step_state_to(100, state100_skip_rdnsequence_item);
            }

            if (l(++state->b < sizeof(rdn_attrtype_prefix))) {
                step_state_to(96, state96_compare_rdnsequence_item_prefix);
            }

            step_state();

        /* RDNSequence: check if last AttributeType byte is 03 (id-at-commonName) */
        case 97:
            if (l(*data != 0x03)) {
                step_state_to(100, state100_skip_rdnsequence_item);
            }
            step_state_to(110, state110_copy_common_name);


state100_skip_rdnsequence_item:
        /* RDNSequence: skip item */
        case 100:
            state->a -= 7;
            statev++;

        case 101:
            if (ul(data_remain() <= state->a)) {
                state->a -= data_remain();
                state->state_remain = state_remain() - data_remain();
                need_more_data();
            }
            data += state->a;
            if (l(state_remain())) {
                go_state(91, state91_rdnsequence_item_begin);
            }
            go_state(115, state115_check_common_name_found);


state110_copy_common_name:
        /* RDNSequence: check id-at-commonName utf8String type tag (0x0c) */
        case 110:
            /* 0x0c = utf8String
             * 0x13 = printableString       a-z, A-Z, ' () +,-.?:/= and SPACE
             * 0x14 = teletexString         8-bit CCITT and T.101 character sets
             * todo: teletexString treated as utf-8 for now
             */
            if (ul((*data != 0x0c) && (*data != 0x13) && (*data != 0x14))) {
                invalid("subject id-at-commonName value has invalid type 0x%02x\n", *data);
            }
            if (ul(state->results.cn_len)) {
                invalid("subject contains more than one id-at-commonName\n");
            }
            step_state();

        /* RDNSequence: get id-at-commonName utf8String length (accept single-byte length only) */
        case 111:
            state->b = state->a - 8 - 1;       /* expected len from outer ASN.1 tag */
            state->a = *data;
            if (ul((!state->a) || (state->a != state->b) || (state->a >= 0x80)
                || (state->a > SSLPARSER_MAX_COMMON_NAME_LEN)))
            {
                invalid("subject id-at-commonName value has invalid length\n");
            }

            state->results.cn_len = state->a;
            state->a = 0;
            step_state();

        /* RDNSequence: copy id-at-commonName utf8String into parser context buffer */
state112_copy_common_name_loop:
        case 112:
            if (ul(*data < 32)) {
                invalid("subject id-at-commonName value contains utf-8 control character %d < 32\n", *data);
            }
            state->results.cn[state->a] = *data;
            if (l(++state->a < state->results.cn_len)) {
                step_state_to(112, state112_copy_common_name_loop);
            }

            debug("cn = \"%s\"\n", state->results.cn);

            if (ul(state_remain() > 1)) {
                step_state_to(91, state91_rdnsequence_item_begin);
            }

            /* done parsing RDNSequence */

            bind_state_remain(state->firstcert_remain + 1);         /* +1 because data is not yet incremented */
            step_state_to(115, state115_check_common_name_found);


state115_check_common_name_found:
        /* check that non-empty id-at-commonName utf8String was found in RDNSequence */
        case 115:
            if (ul(!state->results.cn_len)) {
                invalid("non-empty Common Name (id-at-commonName) not found in certificate");
            }
            go_state(120, state120_find_publickeyinfo);


 state120_find_publickeyinfo:
        /* parse ASN.1: |SubjectPublicKeyInfo ::= SEQUENCE { algorithm .., subjectPublicKey ..}| */
        case 120:
            if (ul(*data != 0x30)) {
                invalid("SubjectPublicKeyInfo has invalid type\n");
            }
            step_state();

        /* SubjectPublicKeyInfo: get outer sequence length (multi-byte accepted) */
        case 121:
            state->b = *data;;

            /* single-byte length */
            if (l(state->b < 0x80)) {
                /* state->b holds actual single-byte length */
                step_state_to(130, state130_check_subjectpublickeyinfo_len);
            }

            /* multi-byte length */
            state->c = state->b & 0x7f;
            if (ul((!state->c) || (state->c > 2))) {
                invalid("SubjectPublicKeyInfo field has invalid length\n");
            }

            state->b = 0;
            step_state();

        /* SubjectPublicKeyInfo: get outer sequence multi-byte length */
state122_get_subjectpublickeyinfo_len:
        case 122:
            state->b = (state->b << 8) | *data;
            if (l(--state->c)) {
                step_state_to(122, state122_get_subjectpublickeyinfo_len);
            }
            step_state_to(130, state130_check_subjectpublickeyinfo_len);


state130_check_subjectpublickeyinfo_len:
        /* SubjectPublicKeyInfo: validate outer sequence length stored in acc2 */
        case 130:
            if (ul((state->b > state_remain()) || (state->b > 512))) {
                invalid("SubjectPublicKeyInfo field has invalid length\n");
            }

            /* state->pk_remain = state->b; */
            state->firstcert_remain = state_remain() - state->b;
            bind_state_remain(state->b);
            go_state(140, state140_parse_publickey_algorithm);


state140_parse_publickey_algorithm:
        /* parse ASN.1: |AlgorithmIdentifier ::= SEQUENCE { algorithm .., parameters .. }| */
        case 140:
            if (ul(*data != 0x30)) {
                invalid("AlgorithmIdentifier has invalid type tag\n");
            }
            step_state();

        /* AlgorithmIdentifier: get outer sequence length */
        case 141:
            state->b = *data;
            if (ul((!state->b) || (state->b > state_remain()) || (state->b >= 64))) {
                invalid("AlgorithmIdentifier has invalid length\n");
            }
            step_state();

        /* AlgorithmIdentifier: check algorithm field type tag (0x06 = OBJECT IDENTIFIER) */
        case 142:
            if (ul(*data != 0x06)) {
                invalid("AlgorithmIdentifier.algorithm has invalid type tag\n");
            }
            step_state();

        /* AlgorithmIdentifier: get algorithm oid field length */
        case 143:
            state->c = *data;
            if (ul((!state->c) || (state->c > state->b - 1)
                || (state->c > SSLPARSER_MAX_PUBLIC_KEY_ALG_OID_BYTELEN - 1)))
            {
                invalid("AlgorithmIdentifier.algorithm has invalid length\n");
            }

            state->results.pubkey_alg_oid[0] = *data;
            state->a = 0;

            step_state();

        /* AlgorithmIdentifier: copy algorithm oid field */
state144_copy_publickey_algorithm:
        case 144:
            state->results.pubkey_alg_oid[state->a + 1] = *data;
            state->a++;
            if (l(state->a < state->results.pubkey_alg_oid[0])) {
                step_state_to(144, state144_copy_publickey_algorithm);
            }

            /* lookup algorithm for oid */
            state->results.pubkey_alg = sslparser_lookup_pubkey_alg_oid(state);

            if (ul(state->debug)) {
                pr_info("xt_sslpin: sslparser: pubkey_alg = { name:%s%s%s, oid_asn1_hex:[",
                    state->results.pubkey_alg ? "\"" : "",
                    state->results.pubkey_alg ? state->results.pubkey_alg->name : "",
                    state->results.pubkey_alg ? "\"" : "");

                if (l(state->results.pubkey_alg_oid[0])) {
                    printhex(state->results.pubkey_alg_oid + 1, state->results.pubkey_alg_oid[0] - 1);
                }
                printk("] }\n");
            }

            statev++;

        /* AlgorithmIdentifier: skip params
         * todo: id-ecPublicKey algo: check ECParameters: namedCurve as part of pk+algo matching */
        case 145:
            /* AlgorithmIdentifier outer sequence length is in state->b
             * AlgorithmIdentifier .algorithm oid field length is in state->c */
            state->b -= state->c + 2;
            statev++;

        case 146:
            if (ul(state->b && (data_remain() <= state->b))) {
                state->b -= data_remain();
                state->state_remain = state_remain() - data_remain();
                need_more_data();
            }
            data += state->b;
            step_state_to(150, state150_parse_publickey);


state150_parse_publickey:
        /* parse ASN.1: |subjectPublicKey BIT STRING| */
        case 150:
            if (ul(*data != 0x03)) {
                invalid("subjectPublicKey has invalid type tag\n");
            }
            step_state();

        /* subjectPublicKey: get bit string length */
        case 151:
            state->b = *data;

            /* single-byte length */
            if (l(state->b < 0x80)) {
                /* state->b holds actual single-byte length */
                step_state_to(160, state160_check_subjectpublickey_len);
            }

            /* multi-byte length */
            state->c = state->b & 0x7f;
            if (ul((!state->c) || (state->c > 2))) {
                invalid("subjectPublicKey has invalid length\n");
            }

            state->b = 0;
            step_state();

        /* subjectPublicKey: get bit string multi-byte length */
state152_get_subjectpublickey_len:
        case 152:
            state->b = (state->b << 8) | *data;
            if (l(--state->c)) {
                step_state_to(152, state152_get_subjectpublickey_len);
            }
            step_state_to(160, state160_check_subjectpublickey_len);


state160_check_subjectpublickey_len:
        /* subjectPublicKey: validate length stored in b */
        case 160:
            if (ul((state->b <= 1) || (state->b != state_remain())
                || (state->b > SSLPARSER_MAX_PUBLIC_KEY_BYTELEN + 1)))
            {
                invalid("subjectPublicKey has invalid length\n");
            }

            state->results.pubkey_len = state->b - 1;
            state->a = 0;

            /* skip bit string first byte indicating n.o. bits padding at end of string */
            step_state();

        /* subjectPublicKey: copy bytes */
state161_copy_subjectpublickey:
        case 161:
            state->results.pubkey[state->a] = *data;
            state->a++;
            if (l(state->a < state->results.pubkey_len)) {
                step_state_to(161, state161_copy_subjectpublickey);
            }

            if (ul(state->debug)) {
                pr_info("xt_sslpin: sslparser: pubkey = [");
                printhex(state->results.pubkey, state->results.pubkey_len);
                printk("]\n");
            }

            bind_state_remain(state->firstcert_remain + 1);
            step_state_to(170, state170_skip_remaining_firstcert);


state170_skip_remaining_firstcert:
        /* Certificate message parsing complete - skip to next SSL/TLS message */
        case 170:
            if (ul(data_remain() < state_remain())) {
                state->state_remain = state_remain() - data_remain();
                need_more_data();
            }
            data += state_remain();

            bind_state_remain(state->msg_remain - 1);
            go_state(171, state171_skip_remaining_certs);

state171_skip_remaining_certs:
        case 171:
            if (ul(data_remain() < state_remain())) {
                state->state_remain = state_remain() - data_remain();
                need_more_data();
            }

            data += state_remain();
            bind_state_remain(state->record_remain - 1);

            if (l(state_remain())) {
                go_state(5, state5_message_begin);
            }

            /* no more messages in record */
            go_state(0, state0_record_begin);

    }

    invalid("error in parser: unhandled state %d\n", statev);
}


#pragma push_macro("step_state_to")
#pragma push_macro("step_state")
#pragma push_macro("_step_state")
#pragma push_macro("step_proto")
#pragma push_macro("state_remain")
#pragma push_macro("bind_state_remain")
#pragma push_macro("data_remain")
#pragma push_macro("go_state")
#pragma push_macro("debug")
#pragma push_macro("need_more_data")
#pragma push_macro("finished")
#pragma push_macro("invalid")
#pragma push_macro("l")
#pragma push_macro("ul")


#endif /* _LINUX_NETFILTER_XT_SSLPIN_SSLPARSER_H */
