/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.persistence.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomRsaPublicKey;
import java.io.IOException;

/**
 * @author robert
 */
public class CustomRsaPublicKeySerializer extends StdSerializer<CustomRsaPublicKey> {

    public CustomRsaPublicKeySerializer() {
        super(CustomRsaPublicKey.class);
    }

    @Override
    public void serialize(CustomRsaPublicKey publicKey, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeStartObject();
        jsonGenerator.writeStringField("format", publicKey.getAlgorithm());
        jsonGenerator.writeStringField("modulus", publicKey.getModulus().toString());
        jsonGenerator.writeStringField("publicExponent", publicKey.getPublicExponent().toString());
        jsonGenerator.writeEndObject();
    }
}
