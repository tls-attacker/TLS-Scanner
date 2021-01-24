/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.persistence.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import de.rub.nds.tlsattacker.attacks.pkcs1.Pkcs1Vector;
import java.io.IOException;

/**
 * @author robert
 */
public class Pkcs1Deserializer extends StdDeserializer<Pkcs1Vector> {

    public Pkcs1Deserializer() {
        super(Pkcs1Vector.class);
    }

    @Override
    public Pkcs1Vector deserialize(JsonParser jp, DeserializationContext dc) throws IOException {

        return null;
    }
}
