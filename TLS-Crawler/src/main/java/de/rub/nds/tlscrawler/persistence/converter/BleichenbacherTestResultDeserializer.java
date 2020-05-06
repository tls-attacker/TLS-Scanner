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
import de.rub.nds.tlsattacker.attacks.pkcs1.Pkcs1Vector;
import de.rub.nds.tlsattacker.attacks.pkcs1.VectorFingerprintPair;
import de.rub.nds.tlsscanner.report.result.bleichenbacher.BleichenbacherTestResult;
import java.io.IOException;

/**
 *
 * @author robert
 */
public class BleichenbacherTestResultDeserializer extends StdDeserializer<BleichenbacherTestResult> {

    public BleichenbacherTestResultDeserializer() {
        super(BleichenbacherTestResult.class);
    }

    @Override
    public BleichenbacherTestResult deserialize(JsonParser jp, DeserializationContext dc) throws IOException, JsonProcessingException {

        return null;
    }
}
