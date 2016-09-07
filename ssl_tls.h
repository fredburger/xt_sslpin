/*
 * ssl_tls.h
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

#ifndef _LINUX_NETFILTER_XT_SSLPIN_SSL_TLS_H
#define _LINUX_NETFILTER_XT_SSLPIN_SSL_TLS_H


#define SSL3_VERSION                    0x0300
#define TLS1_VERSION                    0x0301
#define TLS1_1_VERSION                  0x0302
#define TLS1_2_VERSION                  0x0303

#define SSL3_RT_CHANGE_CIPHER_SPEC      20
#define SSL3_RT_ALERT                   21
#define SSL3_RT_HANDSHAKE               22
#define SSL3_RT_APPLICATION_DATA        23
#define TLS1_RT_HEARTBEAT               24

#define SSL3_MT_HELLO_REQUEST           0
#define SSL3_MT_CLIENT_HELLO            1
#define SSL3_MT_SERVER_HELLO            2
#define TSL1_2_MT_HELLO_VERIFY_REQUEST  3
#define TLS1_MT_NEWSESSIONTICKET        4
/* 5 - 10 unassigned */
#define SSL3_MT_CERTIFICATE             11
#define SSL3_MT_SERVER_KEY_EXCHANGE     12
#define SSL3_MT_CERTIFICATE_REQUEST     13
#define SSL3_MT_SERVER_DONE             14
#define SSL3_MT_CERTIFICATE_VERIFY      15
#define SSL3_MT_CLIENT_KEY_EXCHANGE     16
/* 17 - 19 unassigned */
#define SSL3_MT_FINISHED                20
#define TLS1_2_MT_CERTIFICATE_URL       21
#define TLS1_2_MT_CERTIFICATE_STATUS    22
#define TLS1_2_MT_SUPPLEMENTAL_DATA     23


static inline const char * sslpin_ssl_handshake_mt_to_string(__u8 mt)
{
    switch (mt) {
        case SSL3_MT_HELLO_REQUEST:         return "HelloRequest";
        case SSL3_MT_CLIENT_HELLO:          return "ClientHello";
        case SSL3_MT_SERVER_HELLO:          return "ServerHello";
        case TSL1_2_MT_HELLO_VERIFY_REQUEST:return "HelloVerifyRequest";
        case TLS1_MT_NEWSESSIONTICKET:      return "NewSessioNticket";
        case SSL3_MT_CERTIFICATE:           return "Certificate";
        case SSL3_MT_SERVER_KEY_EXCHANGE:   return "ServerKeyExchange";
        case SSL3_MT_CERTIFICATE_REQUEST:   return "CertificateRequest";
        case SSL3_MT_SERVER_DONE:           return "ServerDone";
        case SSL3_MT_CERTIFICATE_VERIFY:    return "CertificateVerify";
        case SSL3_MT_CLIENT_KEY_EXCHANGE:   return "ClientKeyExchange";
        case SSL3_MT_FINISHED:              return "Finished";
        case TLS1_2_MT_CERTIFICATE_URL:     return "CertificateURL";
        case TLS1_2_MT_CERTIFICATE_STATUS:  return "CertificateStatus";
        case TLS1_2_MT_SUPPLEMENTAL_DATA:   return "SupplementalData";
    }
    return NULL;
}


#endif /* _LINUX_NETFILTER_XT_SSLPIN_SSL_TLS_H */
