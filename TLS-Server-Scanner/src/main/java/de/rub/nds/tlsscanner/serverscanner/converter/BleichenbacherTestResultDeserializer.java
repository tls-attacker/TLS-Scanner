package de.rub.nds.tlsscanner.serverscanner.converter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import de.rub.nds.tlsscanner.serverscanner.report.result.bleichenbacher.BleichenbacherTestResult;

import java.io.IOException;

public class BleichenbacherTestResultDeserializer extends StdDeserializer<BleichenbacherTestResult> {

    public BleichenbacherTestResultDeserializer() {
        super(BleichenbacherTestResult.class);
    }

    @Override
    public BleichenbacherTestResult deserialize(JsonParser jp, DeserializationContext dc) throws IOException {
        // TODO NEED TO BE IMPLEMENTED
        return null;
    }
}
