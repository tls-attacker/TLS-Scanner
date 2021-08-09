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
        // TODO NEED TO BE IMPLEMENTED
        jsonGenerator.writeNull();
    }
}
