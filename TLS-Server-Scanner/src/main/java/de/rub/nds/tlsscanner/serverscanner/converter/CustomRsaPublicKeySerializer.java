package de.rub.nds.tlsscanner.serverscanner.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomRsaPublicKey;

import java.io.IOException;

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
