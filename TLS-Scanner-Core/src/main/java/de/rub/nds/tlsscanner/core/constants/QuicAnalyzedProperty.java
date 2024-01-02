/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.constants;

import de.rub.nds.scanner.core.probe.AnalyzedProperty;
import de.rub.nds.scanner.core.probe.AnalyzedPropertyCategory;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "property")
@XmlAccessorType(XmlAccessType.FIELD)
public enum QuicAnalyzedProperty implements AnalyzedProperty {
    VERSIONS(QuicAnalyzedPropertyCategory.VERSIONS),
    TRANSPORT_PARAMETERS(QuicAnalyzedPropertyCategory.TRANSPORT_PARAMETERS),
    TLS12_HANDSHAKE_DONE(QuicAnalyzedPropertyCategory.QUIRKS),
    TLS12_HANDSHAKE_CONNECTION_CLOSE_FRAME(QuicAnalyzedPropertyCategory.QUIRKS),
    PORT_CONNECTION_MIGRATION_SUCCESSFUL(QuicAnalyzedPropertyCategory.CONNECTION_MIGRATION),
    IPV6_ADDRESS(QuicAnalyzedPropertyCategory.CONNECTION_MIGRATION),
    IPV6_HANDSHAKE_DONE(QuicAnalyzedPropertyCategory.CONNECTION_MIGRATION),
    IPV6_CONNECTION_MIGRATION_SUCCESSFUL(QuicAnalyzedPropertyCategory.CONNECTION_MIGRATION);

    private final QuicAnalyzedPropertyCategory category;

    private QuicAnalyzedProperty(QuicAnalyzedPropertyCategory category) {
        this.category = category;
    }

    @Override
    public AnalyzedPropertyCategory getCategory() {
        return category;
    }

    @Override
    public String getName() {
        return name();
    }
}
