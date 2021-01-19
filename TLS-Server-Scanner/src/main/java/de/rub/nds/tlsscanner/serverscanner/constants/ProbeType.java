/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.constants;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public enum ProbeType {
    ESNI,
    CERTIFICATE,
    OCSP,
    CIPHERSUITE_ORDER,
    CIPHERSUITE,
    HEARTBLEED,
    HTTP_HEADER,
    BLEICHENBACHER,
    DROWN,
    EARLY_CCS,
    NAMED_GROUPS,
    PADDING_ORACLE,
    POODLE,
    TLS_POODLE,
    PROTOCOL_VERSION,
    INVALID_CURVE,
    SIGNATURE_AND_HASH,
    EXTENSIONS,
    TOKENBINDING,
    COMPRESSIONS,
    COMMON_BUGS,
    RESUMPTION,
    RENEGOTIATION,
    SESSION_TICKET_ZERO_KEY,
    SNI,
    HANDSHAKE_SIMULATION,
    TLS13,
    MAC,
    CCA_SUPPORT,
    CCA_REQUIRED,
    CCA,
    DIRECT_RACCOON,
    EC_POINT_FORMAT,
    RACCOON_ATTACK,
    DTLS_COOKIE,
    DTLS_CCS,
    DTLS_FRAGMENTATION
}
