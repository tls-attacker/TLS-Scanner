package de.rub.nds.tlsscanner.serverscanner.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import de.rub.nds.tlsattacker.core.crypto.ec.FieldElement;

import java.io.IOException;

public class FieldElementDeserializer extends StdDeserializer<FieldElement> {

    public FieldElementDeserializer() {
        super(FieldElement.class);
    }

    @Override
    public FieldElement deserialize(JsonParser jp, DeserializationContext dc) throws IOException {
        // TODO NEED TO BE IMPLEMENTED
        return null;
    }
}
