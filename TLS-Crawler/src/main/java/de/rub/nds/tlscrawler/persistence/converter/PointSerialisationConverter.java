/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.persistence.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import java.io.IOException;

public class PointSerialisationConverter extends StdSerializer<Point> {

    public PointSerialisationConverter() {
        super(Point.class);
    }

    @Override
    public void serialize(Point point, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeStartObject();
        jsonGenerator.writeStringField("x", point.getX().getData().toString());
        jsonGenerator.writeStringField("y", point.getY().getData().toString());
        jsonGenerator.writeEndObject();
    }
}
