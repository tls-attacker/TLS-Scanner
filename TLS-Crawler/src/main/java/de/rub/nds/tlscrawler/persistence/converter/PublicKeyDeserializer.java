/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.persistence.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import java.io.IOException;
import java.security.PublicKey;

/**
 * @author robert
 */
public class PublicKeyDeserializer extends StdDeserializer<PublicKey> {

    public PublicKeyDeserializer() {
        super(PublicKey.class);
    }

    @Override
    public PublicKey deserialize(JsonParser jp, DeserializationContext dc) throws IOException {
        JsonNode node = jp.getCodec().readTree(jp);
        //  System.out.println(node);
        return null;
    }
}
