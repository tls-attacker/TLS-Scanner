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
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import java.io.IOException;

/**
 * @author robert
 */
public class PointDeserializer extends StdDeserializer<Point> {

    public PointDeserializer() {
        super(Point.class);
    }

    @Override
    public Point deserialize(JsonParser jp, DeserializationContext dc) throws IOException {
        JsonNode node = jp.getCodec().readTree(jp);
        //System.out.println(node);
        return null;
    }
}
