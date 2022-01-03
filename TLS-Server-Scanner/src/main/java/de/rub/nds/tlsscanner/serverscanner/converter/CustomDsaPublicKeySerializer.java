/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDsaPublicKey;

import java.io.IOException;

public class CustomDsaPublicKeySerializer extends StdSerializer<CustomDsaPublicKey> {

    public CustomDsaPublicKeySerializer() {
        super(CustomDsaPublicKey.class);
    }

    @Override
    public void serialize(CustomDsaPublicKey publicKey, JsonGenerator jsonGenerator,
        SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeStartObject();
        jsonGenerator.writeStringField("format", publicKey.getAlgorithm());
        jsonGenerator.writeStringField("publicKey", publicKey.getY().toString());
        jsonGenerator.writeStringField("p", publicKey.getDsaP().toString());
        jsonGenerator.writeStringField("q", publicKey.getDsaQ().toString());
        jsonGenerator.writeStringField("g", publicKey.getDsaG().toString());
        jsonGenerator.writeEndObject();
    }
}
