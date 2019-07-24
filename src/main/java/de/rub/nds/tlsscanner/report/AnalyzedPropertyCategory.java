/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report;

public enum AnalyzedPropertyCategory {
    SUPPORTED_VERSIONS,
    SUPPORTED_CIPHERSUITS,
    EXTENSIONS,
    SESSION_RESUMPTION,
    RENEGOTIATION,
    HTTPS_HEADERS,
    QUIRKS,
    ATTACKS,
    COMPARISSON_FAILURE,
    CERTIFICATE,
    FRESHNES,
    SNI,
    COMPRESSION,
    FFDHE,
    BEST_PRACTICE,
    EC,
}
