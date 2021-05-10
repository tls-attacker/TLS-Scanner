/**
 * TLS-Crawler - A tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2021 Paderborn University, Ruhr University Bochum
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import de.rub.nds.asn1.Asn1Encodable;
import java.io.IOException;

public class Asn1EncodableSerializer extends StdSerializer<Asn1Encodable> {

    public Asn1EncodableSerializer() {
        super(Asn1Encodable.class);
    }

    @Override
    public void serialize(Asn1Encodable asn1Encodable, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeNull();
    }
}
