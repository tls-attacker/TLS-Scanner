/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import de.rub.nds.protocol.crypto.ec.FieldElement;
import java.io.IOException;

public class FieldElementDeserializer extends StdDeserializer<FieldElement> {

    public FieldElementDeserializer() {
        super(FieldElement.class);
    }

    @Override
    public FieldElement deserialize(JsonParser jp, DeserializationContext dc) throws IOException {
        // TODO NEED TO BE IMPLEMENTED
        return null;
    }
}
