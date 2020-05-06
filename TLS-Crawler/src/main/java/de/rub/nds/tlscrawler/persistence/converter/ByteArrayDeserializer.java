/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.persistence.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.bouncycastle.crypto.tls.Certificate;

/**
 *
 * @author robert
 */
public class ByteArrayDeserializer extends StdDeserializer<byte[]> {

    public ByteArrayDeserializer() {
        super(byte[].class);
    }

    @Override
    public byte[] deserialize(JsonParser jp, DeserializationContext dc) throws IOException, JsonProcessingException {
        return null;
    }
}
