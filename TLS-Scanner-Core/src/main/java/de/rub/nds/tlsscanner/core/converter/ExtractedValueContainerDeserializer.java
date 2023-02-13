/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import java.io.IOException;

public class ExtractedValueContainerDeserializer extends StdDeserializer<ExtractedValueContainer> {

    public ExtractedValueContainerDeserializer() {
        super(ExtractedValueContainer.class);
    }

    @Override
    public ExtractedValueContainer deserialize(JsonParser jp, DeserializationContext dc)
            throws IOException {
        JsonNode node = jp.getCodec().readTree(jp);
        TrackableValueType type = TrackableValueType.valueOf(node.get("type").asText());
        // TODO THIS HAS TO HAVE A FULL IMPLEMENTATION
        return new ExtractedValueContainer(type);
    }
}
