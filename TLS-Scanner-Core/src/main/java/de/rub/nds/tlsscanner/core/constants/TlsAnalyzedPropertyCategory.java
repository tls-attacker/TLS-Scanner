/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.constants;

import de.rub.nds.scanner.core.probe.AnalyzedPropertyCategory;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public enum TlsAnalyzedPropertyCategory implements AnalyzedPropertyCategory {
    CONNECTION,
    ESNI,
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
    CERTIFICATE_TRANSPARENCY,
    OCSP,
    FRESHNESS,
    SNI,
    COMPRESSION,
    EC,
    FFDHE,
    BEST_PRACTICES,
    DTLS,
    HELLO_VERIFY_REQUEST,
    MAC,
    HELLO_RETRY_REQUEST,
    APPLICATION_LAYER,
    CLIENT_ADVERTISED
}
