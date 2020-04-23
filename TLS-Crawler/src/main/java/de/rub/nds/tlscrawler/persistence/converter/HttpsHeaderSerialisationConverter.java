/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.persistence.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import java.io.IOException;

public class HttpsHeaderSerialisationConverter extends StdSerializer<HttpsHeader> {

    public HttpsHeaderSerialisationConverter() {
        super(HttpsHeader.class);
    }

    @Override
    public void serialize(HttpsHeader header, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeStartObject();
        jsonGenerator.writeStringField("header", header.getHeaderName().getValue());
        jsonGenerator.writeStringField("value", header.getHeaderValue().getValue());
        jsonGenerator.writeEndObject();
    }
}
