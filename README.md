## NAME

xt_sslpin - netfilter/xtables module: match SSL/TLS certificate public key (pinning)


## SYNOPSIS

    iptables -I <chain> .. -m sslpin [!] --pubkey <alg>:<pubkey-hex> [--debug] ..


## DESCRIPTION

For an introduction to SSL/TLS certificate pinning, see: https://www.owasp.org/index.php/Pinning_Cheat_Sheet

xt_sslpin lets you do certificate validation/pinning at the netfilter level.

xt_sslpin will only validate the public key (with minimal performance impact), and applications are expected to do further certificate chain validation and signature checks (i.e. normal SSL/TLS processing).


## EXAMPLE

    iptables -I INPUT -m conntrack --ctstate ESTABLISHED -p tcp --sport 443 \
        -m sslpin --debug --pubkey rsa:000000000000000000000000000000000000000000000000000000000000000000000000000 \
        -j DROP

## INSTALLATION

    git clone git://github.com/fredburger/xt_sslpin
    cd xt_sslpin
    sudo apt-get install iptables-dev # xtables.h

Build and install:

    make
    sudo make install

Verify install:

    iptables -m sslpin -h

Usage: _See Example and Options sections._


##### Uninstalling

Clean source/build directory:

    make clean

Uninstall:

    sudo make uninstall


## OPTIONS

Options preceded by an exclamation point negate the comparison: the rule will match if the presented SSL/TLS certificate does NOT have the specified public key.


### `[!] --pubkey <alg>:<pubkey-hex>`

If a "Certificate" message is seen, match if the certificate has the specified public key.

`<alg>` denotes the expected Public Key Algorithm, and can be one of the following: *rsa, dsa, ec*.

`<pubkey-hex>` is the subjectPublicKey as hex bytes, e.g.: `0011223344`.

(_The `--debug` option can be used to get the public key for a site/IP._)



### `--debug`

Verbose logging.

    kernel: [ 154.806189] xt_sslpin 1.0 (SSL/TLS pinning)
    kernel: [ 156.976209] xt_sslpin: 1 connection (0 actively monitored)
    kernel: [ 156.127355] xt_sslpin: 1 connection (1 actively monitored)
    kernel: [ 157.127367] xt_sslpin: sslparser: ServerHello handshake message (len = 85)
    kernel: [ 157.127370] xt_sslpin: sslparser: Certificate handshake message (len = 2193)
    kernel: [ 157.127373] xt_sslpin: sslparser: cn = "example.com"
    kernel: [ 157.127378] xt_sslpin: sslparser: pubkey_alg = { name:"rsa", oid_asn1_hex:[2a864886f...] }
    kernel: [ 157.127387] xt_sslpin: sslparser: pubkey = [00000000000000000000000000000000...]
    kernel: [ 159.129145] xt_sslpin: sslparser: ServerDone handshake message (len = 0)
    kernel: [ 159.285698] xt_sslpin: sslparser: ChangeCipherSpec record
    kernel: [ 159.285714] xt_sslpin: rule not matched (cn = "example.com")
    kernel: [ 159.344721] xt_sslpin: 1 connection (0 actively monitored)


## IMPLEMENTATION NOTES

Per connection, the incoming handshake data is parsed once across all -m sslpin iptables rules;
upon receiving the SSL/TLS handshake ChangeCipherSpec message, the parsed certificate is checked by all rules.

After this, the connection is marked as "finished", and xt_sslpin will not do any further checking.
(Re-handshaking will not be checked in order to incur minimal overhead, and as the server has already proved
its identity).

Up until the ChangeCipherSpec message is received, xt_sslpin will drop out-of-order TCP segments to
parse the data linearly without buffering. Conntrack takes care of IP fragment reassembly up-front, but packets
can still have non-linear memory layout; see skb_is_nonlinear().

If SYN is received on a time-wait state conn/flow, conntrack will destroy the old cf_conn
and create a new cf_conn. Thus, our per-conn state transitions are simply new->open->destroyed (no reopen).


## TODO

* ECParameters/namedCurve pinning in addition to current alg+pubkey pinning
* Optional buffering for reordered TCP segments during handshake (no RTT penalty / overhead)
* TCP Fast Open (TFO) support
* Restrict TCP Options / TCP stack passthrough
* IPv6 support


## LICENSE

xt_sslpin is Copyright (C) 2010-2013 fredburger (github.com/fredburger).

This program is free software; you can redistribute it and/or modify it under the terms of the
GNU General Public License as published by the Free Software Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to
the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

