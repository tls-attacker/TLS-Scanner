/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.io;

import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlElementDecl;
import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;

@XmlRegistry
public class TlsAnalyzedPropertyFactory {
    @XmlElementDecl(name = "analyzedProperty")
    public JAXBElement<TlsAnalyzedProperty> createTlsAnalyzedProperty(TlsAnalyzedProperty property) {
        return new JAXBElement<TlsAnalyzedProperty>(new QName("tlsAnalyzedProperty"), TlsAnalyzedProperty.class,
            property);
    }
}
