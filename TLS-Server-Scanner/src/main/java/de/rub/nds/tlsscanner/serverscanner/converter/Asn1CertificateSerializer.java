package de.rub.nds.tlsscanner.serverscanner.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import org.bouncycastle.asn1.x509.Certificate;

import java.io.IOException;

public class Asn1CertificateSerializer extends StdSerializer<Certificate> {

    public Asn1CertificateSerializer() {
        super(Certificate.class);
    }

    @Override
    public void serialize(Certificate certificate, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeString(ArrayConverter.bytesToHexString(certificate.getEncoded(), false, false).replace(" ", ""));
    }
}
