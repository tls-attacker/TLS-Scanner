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
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsscanner.core.constants.CertificateLength;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.tls.Certificate;

public class CertificateDeserializer extends StdDeserializer<Certificate> {

    public CertificateDeserializer() {
        super(Certificate.class);
    }

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public Certificate deserialize(JsonParser jp, DeserializationContext dc) throws IOException {
        try {
            JsonNode node = jp.getCodec().readTree(jp);
            String encodedCerts = node.get("certificates").asText();
            String[] splitedStrings = encodedCerts.split(",");
            org.bouncycastle.asn1.x509.Certificate[] certs =
                    new org.bouncycastle.asn1.x509.Certificate[splitedStrings.length];
            int i = 0;
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            for (String split : splitedStrings) {
                split = split.replace("\n", "");
                split = split.replace(" ", "");

                byte[] cert = ArrayConverter.hexStringToByteArray(split);
                stream.write(
                        ArrayConverter.intToBytes(cert.length, CertificateLength.TWO.getLength()));
                stream.write(cert);
                i++;
            }
            Certificate cert =
                    Certificate.parse(
                            new ByteArrayInputStream(
                                    ArrayConverter.concatenate(
                                            ArrayConverter.intToBytes(
                                                    stream.toByteArray().length,
                                                    CertificateLength.THREE.getLength()),
                                            stream.toByteArray())));
            return cert;
        } catch (Exception E) {
            LOGGER.error("Could not deserialize certificate", E);
            return null;
        }
    }
}
