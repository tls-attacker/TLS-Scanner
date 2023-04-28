/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.modifiablevariable.util.ArrayConverter;

import java.io.IOException;

public class Asn1FieldSerializer extends StdSerializer<Asn1Field> {

    public Asn1FieldSerializer() {
        super(Asn1Field.class);
    }

    @Override
    public void serialize(
            Asn1Field asn1Field, JsonGenerator jsonGenerator, SerializerProvider serializerProvider)
            throws IOException {
        jsonGenerator.writeStartObject();
        jsonGenerator.writeStringField(
                "Asn1Field",
                ArrayConverter.bytesToHexString(asn1Field.getSerializer().serialize(), false));
        jsonGenerator.writeEndObject();
    }
}
