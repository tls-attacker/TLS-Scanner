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
import de.rub.nds.protocol.crypto.ec.FieldElement;
import java.io.IOException;

public class FieldElementSerializer extends StdSerializer<FieldElement> {

    public FieldElementSerializer() {
        super(FieldElement.class);
    }

    @Override
    public void serialize(
            FieldElement fieldElement,
            JsonGenerator jsonGenerator,
            SerializerProvider serializerProvider)
            throws IOException {
        // TODO NEED TO BE IMPLEMENTED
        jsonGenerator.writeNull();
    }
}
