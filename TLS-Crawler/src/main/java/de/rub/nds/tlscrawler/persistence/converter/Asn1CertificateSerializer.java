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
import org.bouncycastle.asn1.x509.Certificate;

/**
 * @author robert
 */
public class Asn1CertificateSerializer extends StdSerializer<Certificate> {

    public Asn1CertificateSerializer() {
        super(Certificate.class);
    }

    @Override
    public void serialize(Certificate certificate, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeString(ArrayConverter.bytesToHexString(certificate.getEncoded(), false, false).replace(" ", ""));
    }
}
