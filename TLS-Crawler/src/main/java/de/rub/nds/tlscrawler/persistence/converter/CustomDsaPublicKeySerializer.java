/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.persistence.converter;

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
        jsonGenerator.writeStringField("p", publicKey.getP().toString());
        jsonGenerator.writeStringField("q", publicKey.getQ().toString());
        jsonGenerator.writeStringField("g", publicKey.getG().toString());
        jsonGenerator.writeEndObject();
    }
}
