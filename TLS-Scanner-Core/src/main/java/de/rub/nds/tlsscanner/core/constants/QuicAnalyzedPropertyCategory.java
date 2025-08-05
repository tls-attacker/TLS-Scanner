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
public enum QuicAnalyzedPropertyCategory implements AnalyzedPropertyCategory {
    VERSIONS,
    TRANSPORT_PARAMETERS,
    CONNECTION_MIGRATION,
    QUIRKS,
    RETRY_PACKET,
    NEW_CONNECTION_ID_FRAME,
    NEW_TOKEN_FRAME,
    FRAGMENTATION,
}
