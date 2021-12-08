/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import org.bouncycastle.crypto.tls.Certificate;

import java.io.IOException;

public class CertificateSerializer extends StdSerializer<Certificate> {

    public CertificateSerializer() {
        super(Certificate.class);
    }

    @Override
    public void serialize(Certificate certificate, JsonGenerator jsonGenerator, SerializerProvider serializerProvider)
        throws IOException {
        jsonGenerator.writeStartObject();
        jsonGenerator.writeArrayFieldStart("certificates");
        for (org.bouncycastle.asn1.x509.Certificate cert : certificate.getCertificateList()) {
            jsonGenerator
                .writeString(ArrayConverter.bytesToHexString(cert.getEncoded(), false, false).replace(" ", ""));
        }
        jsonGenerator.writeEndArray();
        jsonGenerator.writeEndObject();
    }
}
