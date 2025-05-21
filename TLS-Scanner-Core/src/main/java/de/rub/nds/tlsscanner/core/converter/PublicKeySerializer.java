/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import java.io.IOException;
import java.security.PublicKey;
import java.util.Base64;

public class PublicKeySerializer extends StdSerializer<PublicKey> {

    public PublicKeySerializer() {
        super(PublicKey.class);
    }

    @Override
    public void serialize(
            PublicKey publicKey, JsonGenerator jsonGenerator, SerializerProvider serializerProvider)
            throws IOException {
        jsonGenerator.writeStartObject();

        // Basic implementation - stores algorithm and encoded key
        if (publicKey != null) {
            jsonGenerator.writeStringField("algorithm", publicKey.getAlgorithm());
            jsonGenerator.writeStringField("format", publicKey.getFormat());
            jsonGenerator.writeStringField(
                    "encoded", Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        } else {
            // Following the pattern from the deserializer which has a TODO note
            // TODO NEED TO BE IMPLEMENTED
            jsonGenerator.writeNullField("algorithm");
            jsonGenerator.writeNullField("format");
            jsonGenerator.writeNullField("encoded");
        }

        jsonGenerator.writeEndObject();
    }
}
