/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.serverscanner.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomEcPublicKey;

import java.io.IOException;

/**
 * @author robert
 */
public class CustomEcPublicKeySerializer extends StdSerializer<CustomEcPublicKey> {

    public CustomEcPublicKeySerializer() {
        super(CustomEcPublicKey.class);
    }

    @Override
    public void serialize(CustomEcPublicKey publicKey, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeStartObject();
        jsonGenerator.writeStringField("format", publicKey.getAlgorithm());
        String curve = publicKey.getGroup() != null ? publicKey.getGroup().name() : publicKey.getGostCurve().name();
        jsonGenerator.writeStringField("curve", curve);
        jsonGenerator.writeStringField("x", publicKey.getPoint().getFieldX().getData().toString());
        jsonGenerator.writeStringField("y", publicKey.getPoint().getFieldY().getData().toString());
        jsonGenerator.writeEndObject();
    }
}
