package de.rub.nds.tlsscanner.serverscanner.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.bouncycastle.asn1.x509.Certificate;

public class Asn1CertificateDeserializer extends StdDeserializer<Certificate> {

    public Asn1CertificateDeserializer() {
        super(Certificate.class);
    }

    @Override
    public Certificate deserialize(JsonParser jp, DeserializationContext dc) {
        // TODO NEED TO BE IMPLEMENTED
        return null;
    }
}
