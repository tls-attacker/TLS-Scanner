package de.rub.nds.tlsscanner.serverscanner.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import de.rub.nds.tlsattacker.attacks.pkcs1.Pkcs1Vector;

import java.io.IOException;

public class Pkcs1Deserializer extends StdDeserializer<Pkcs1Vector> {

    public Pkcs1Deserializer() {
        super(Pkcs1Vector.class);
    }

    @Override
    public Pkcs1Vector deserialize(JsonParser jp, DeserializationContext dc) throws IOException {
        // TODO NEED TO BE IMPLEMENTED
        return null;
    }
}
