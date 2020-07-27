/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.report;

public enum AnalyzedPropertyCategory {
    SESSION_TICKET,
    VERSIONS,
    CIPHER_SUITES,
    EXTENSIONS,
    SESSION_RESUMPTION,
    RENEGOTIATION,
    HTTPS_HEADERS,
    QUIRKS,
    ATTACKS,
    COMPARISON_FAILURE,
    CERTIFICATE,
    FRESHNESS,
    SNI,
    COMPRESSION,
    EC,
    FFDHE,
    BEST_PRACTICES,
}
