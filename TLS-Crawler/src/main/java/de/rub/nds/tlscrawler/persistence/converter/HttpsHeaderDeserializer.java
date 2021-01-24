/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.persistence.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import java.io.IOException;

/**
 * @author robert
 */
public class HttpsHeaderDeserializer extends StdDeserializer<HttpsHeader> {

    public HttpsHeaderDeserializer() {
        super(HttpsHeader.class);
    }

    @Override
    public HttpsHeader deserialize(JsonParser jp, DeserializationContext dc) throws IOException {

        return null;
    }
}
