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
import de.rub.nds.tlsattacker.core.crypto.keys.CustomEcPublicKey;
import java.io.IOException;

public class CustomEcPublicKeySerializer extends StdSerializer<CustomEcPublicKey> {

    public CustomEcPublicKeySerializer() {
        super(CustomEcPublicKey.class);
    }

    @Override
    public void serialize(CustomEcPublicKey publicKey, JsonGenerator jsonGenerator,
        SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeStartObject();
        jsonGenerator.writeStringField("format", publicKey.getAlgorithm());
        String curve = publicKey.getGroup() != null ? publicKey.getGroup().name() : publicKey.getGostCurve().name();
        jsonGenerator.writeStringField("curve", curve);
        jsonGenerator.writeStringField("x", publicKey.getPoint().getFieldX().getData().toString());
        jsonGenerator.writeStringField("y", publicKey.getPoint().getFieldY().getData().toString());
        jsonGenerator.writeEndObject();
    }
}
