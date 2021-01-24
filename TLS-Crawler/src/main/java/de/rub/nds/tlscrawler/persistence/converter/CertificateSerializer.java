/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.persistence.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.io.IOException;
import org.bouncycastle.crypto.tls.Certificate;

/**
 * @author robert
 */
public class CertificateSerializer extends StdSerializer<Certificate> {

    public CertificateSerializer() {
        super(Certificate.class);
    }

    @Override
    public void serialize(Certificate certificate, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeStartObject();
        jsonGenerator.writeArrayFieldStart("certificates");
        for (org.bouncycastle.asn1.x509.Certificate cert : certificate.getCertificateList()) {
            jsonGenerator.writeString(ArrayConverter.bytesToHexString(cert.getEncoded(), false, false).replace(" ", ""));
        }
        jsonGenerator.writeEndArray();
        jsonGenerator.writeEndObject();
    }
}
