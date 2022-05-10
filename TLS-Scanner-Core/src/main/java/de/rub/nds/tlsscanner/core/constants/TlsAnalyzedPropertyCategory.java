/**
 * TLS-Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.core.constants;

import de.rub.nds.scanner.core.constants.AnalyzedPropertyCategory;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public enum TlsAnalyzedPropertyCategory implements AnalyzedPropertyCategory {
    ESNI,
    VERSIONS,
    SESSION_TICKET,
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
    HELLO_VERIFY_REQUEST,
    LIST,
	MAP,
	SET;
}
