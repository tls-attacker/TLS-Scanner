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
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDhPublicKey;
import java.io.IOException;

public class CustomDhPublicKeySerializer extends StdSerializer<CustomDhPublicKey> {

    public CustomDhPublicKeySerializer() {
        super(CustomDhPublicKey.class);
    }

    @Override
    public void serialize(CustomDhPublicKey publicKey, JsonGenerator jsonGenerator,
        SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeStartObject();
        jsonGenerator.writeStringField("format", publicKey.getAlgorithm());
        jsonGenerator.writeStringField("publicKey", publicKey.getY().toString());
        jsonGenerator.writeStringField("generator", publicKey.getGenerator().toString());
        jsonGenerator.writeStringField("modulus", publicKey.getModulus().toString());
        jsonGenerator.writeEndObject();
    }
}
