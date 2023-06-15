/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.io;

import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.annotation.XmlElementDecl;
import jakarta.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;

@XmlRegistry
public class TlsAnalyzedPropertyFactory {
    @XmlElementDecl(name = "analyzedProperty")
    public JAXBElement<TlsAnalyzedProperty> createTlsAnalyzedProperty(
            TlsAnalyzedProperty property) {
        return new JAXBElement<TlsAnalyzedProperty>(
                new QName("tlsAnalyzedProperty"), TlsAnalyzedProperty.class, property);
    }
}
