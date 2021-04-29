/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.serverscanner.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDsaPublicKey;

import java.io.IOException;

/**
 * @author robert
 */
public class CustomDsaPublicKeySerializer extends StdSerializer<CustomDsaPublicKey> {

    public CustomDsaPublicKeySerializer() {
        super(CustomDsaPublicKey.class);
    }

    @Override
    public void serialize(CustomDsaPublicKey publicKey, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeStartObject();
        jsonGenerator.writeStringField("format", publicKey.getAlgorithm());
        jsonGenerator.writeStringField("publicKey", publicKey.getY().toString());
        jsonGenerator.writeStringField("p", publicKey.getDsaP().toString());
        jsonGenerator.writeStringField("q", publicKey.getDsaQ().toString());
        jsonGenerator.writeStringField("g", publicKey.getDsaG().toString());
        jsonGenerator.writeEndObject();
    }
}
