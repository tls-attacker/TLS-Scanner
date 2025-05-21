/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import java.io.IOException;

public class ExtractedValueContainerSerializer extends StdSerializer<ExtractedValueContainer<?>> {

    @SuppressWarnings("unchecked")
    public ExtractedValueContainerSerializer() {
        super((Class<ExtractedValueContainer<?>>) (Class<?>) ExtractedValueContainer.class);
    }

    @Override
    public void serialize(
            ExtractedValueContainer<?> container,
            JsonGenerator jsonGenerator,
            SerializerProvider serializerProvider)
            throws IOException {
        jsonGenerator.writeStartObject();
        // TrackableValueType is an enum implementing TrackableValue
        if (container.getType() instanceof Enum) {
            jsonGenerator.writeStringField("type", ((Enum<?>) container.getType()).name());
        } else {
            jsonGenerator.writeStringField("type", container.getType().toString());
        }
        // TODO THIS HAS TO HAVE A FULL IMPLEMENTATION

        jsonGenerator.writeEndObject();
    }
}
