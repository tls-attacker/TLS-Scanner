/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.constants;

/**
 *
 * @author Robert Merget - {@literal <robert.merget@rub.de>}
 */
public enum ProbeType {
    ALPN,
    ESNI,
    CERTIFICATE,
    OCSP,
    CIPHER_SUITE_ORDER,
    CERTIFICATE_TRANSPARENCY,
    CIPHER_SUITE,
    HEARTBLEED,
    HTTP_HEADER,
    BLEICHENBACHER,
    DROWN,
    EARLY_CCS,
    NAMED_GROUPS,
    PADDING_ORACLE,
    TLS_POODLE,
    PROTOCOL_VERSION,
    INVALID_CURVE,
    SIGNATURE_AND_HASH,
    EXTENSIONS,
    TOKENBINDING,
    COMPRESSIONS,
    COMMON_BUGS,
    RECORD_FRAGMENTATION,
    RESUMPTION,
    RENEGOTIATION,
    SESSION_TICKET_ZERO_KEY,
    SNI,
    HANDSHAKE_SIMULATION,
    MAC,
    CCA_SUPPORT,
    CCA_REQUIRED,
    CCA,
    DIRECT_RACCOON,
    EC_POINT_FORMAT,
    RACCOON_ATTACK,
    HTTP_FALSE_START,
    HELLO_RETRY,
    CROSS_PROTOCOL_ALPACA,
    RNG,
    HTTP_FALSE_START
}
