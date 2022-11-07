/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import de.rub.nds.tlsscanner.core.vector.Vector;
import java.io.IOException;

public class VectorDeserializer extends StdDeserializer<Vector> {

    public VectorDeserializer() {
        super(Vector.class);
    }

    @Override
    public Vector deserialize(JsonParser jp, DeserializationContext dc) throws IOException {
        JsonNode node = jp.getCodec().readTree(jp);
        String name = node.asText();
        return new Vector() {
            @Override
            public String getName() {
                return name;
            }

            @Override
            public boolean equals(Object o) {
                if (o instanceof Vector) {
                    return ((Vector) o).getName().equals(this.getName());
                } else {
                    return false;
                }
            }

            @Override
            public int hashCode() {
                return this.getName().hashCode();
            }
        };
    }
}
