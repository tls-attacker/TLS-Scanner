/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import de.rub.nds.tlsattacker.core.http.header.HttpHeader;
import java.io.IOException;

public class HttpsHeaderDeserializer extends StdDeserializer<HttpHeader> {

    public HttpsHeaderDeserializer() {
        super(HttpHeader.class);
    }

    @Override
    public HttpHeader deserialize(JsonParser jp, DeserializationContext dc) throws IOException {
        // TODO NEED TO BE IMPLEMENTED
        return null;
    }
}
