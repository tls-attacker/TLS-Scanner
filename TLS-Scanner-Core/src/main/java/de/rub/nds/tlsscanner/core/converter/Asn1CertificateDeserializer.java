/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.bouncycastle.asn1.x509.Certificate;

public class Asn1CertificateDeserializer extends StdDeserializer<Certificate> {

    public Asn1CertificateDeserializer() {
        super(Certificate.class);
    }

    @Override
    public Certificate deserialize(JsonParser jp, DeserializationContext dc) {
        // TODO NEED TO BE IMPLEMENTED
        return null;
    }
}
