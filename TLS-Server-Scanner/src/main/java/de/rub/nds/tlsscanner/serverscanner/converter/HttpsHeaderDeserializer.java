package de.rub.nds.tlsscanner.serverscanner.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;

import java.io.IOException;

public class HttpsHeaderDeserializer extends StdDeserializer<HttpsHeader> {

    public HttpsHeaderDeserializer() {
        super(HttpsHeader.class);
    }

    @Override
    public HttpsHeader deserialize(JsonParser jp, DeserializationContext dc) throws IOException {
        // TODO NEED TO BE IMPLEMENTED
        return null;
    }
}
