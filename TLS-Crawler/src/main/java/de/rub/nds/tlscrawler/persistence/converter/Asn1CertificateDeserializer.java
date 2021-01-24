/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.persistence.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import java.io.IOException;
import org.bouncycastle.asn1.x509.Certificate;

/**
 * @author robert
 */
public class Asn1CertificateDeserializer extends StdDeserializer<Certificate> {

    public Asn1CertificateDeserializer() {
        super(Certificate.class);
    }

    @Override
    public Certificate deserialize(JsonParser jp, DeserializationContext dc) throws IOException {
        return null;

    }
}
