/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

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
