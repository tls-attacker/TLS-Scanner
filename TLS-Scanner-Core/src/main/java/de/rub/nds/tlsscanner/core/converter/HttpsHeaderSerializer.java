/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import java.io.IOException;

public class HttpsHeaderSerializer extends StdSerializer<HttpsHeader> {

    public HttpsHeaderSerializer() {
        super(HttpsHeader.class);
    }

    @Override
    public void serialize(
            HttpsHeader header, JsonGenerator jsonGenerator, SerializerProvider serializerProvider)
            throws IOException {
        jsonGenerator.writeStartObject();
        jsonGenerator.writeStringField("header", header.getHeaderName().getValue());
        jsonGenerator.writeStringField("value", header.getHeaderValue().getValue());
        jsonGenerator.writeEndObject();
    }
}
