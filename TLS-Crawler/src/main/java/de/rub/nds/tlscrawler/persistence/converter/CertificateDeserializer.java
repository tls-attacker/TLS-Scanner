/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.persistence.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.bouncycastle.crypto.tls.Certificate;

/**
 *
 * @author robert
 */
public class CertificateDeserializer extends StdDeserializer<Certificate> {

    public CertificateDeserializer() {
        super(Certificate.class);
    }

    @Override
    public Certificate deserialize(JsonParser jp, DeserializationContext dc) throws IOException, JsonProcessingException {
        try {
            JsonNode node = jp.getCodec().readTree(jp);
            String encodedCerts = node.get("certificates").asText();
            String[] splitedStrings = encodedCerts.split(",");
            org.bouncycastle.asn1.x509.Certificate[] certs = new org.bouncycastle.asn1.x509.Certificate[splitedStrings.length];
            int i = 0;
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            for (String split : splitedStrings) {
                split = split.replace("\n", "");
                split = split.replace(" ", "");

                byte[] cert = ArrayConverter.hexStringToByteArray(split);
                stream.write(ArrayConverter.intToBytes(cert.length, 2));
                stream.write(cert);
                i++;
            }
            Certificate cert = Certificate.parse(new ByteArrayInputStream(ArrayConverter.concatenate(ArrayConverter.intToBytes(stream.toByteArray().length, 3), stream.toByteArray())));
            return cert;
        } catch (Exception E) {
            //E.printStackTrace();
            return null;
        }
    }
}
