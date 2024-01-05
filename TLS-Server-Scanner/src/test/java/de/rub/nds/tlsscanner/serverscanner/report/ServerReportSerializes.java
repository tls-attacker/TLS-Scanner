/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidDefinitionException;
import de.rub.nds.scanner.core.probe.AnalyzedProperty;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag(TestCategories.INTEGRATION_TEST)
class ServerReportSerializesTest {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final ObjectMapper mapper = new ObjectMapper();

    static {
        for (Module modules : ServerReport.getSerializerModules()) {
            mapper.registerModule(modules);
        }
    }

    public ServerReportSerializesTest() {}

    static String serialize(ServerReport report) throws JsonProcessingException {
        return mapper.writeValueAsString(report);
    }

    static ServerReport deserialize(String json) throws JsonProcessingException {
        return mapper.readValue(json, ServerReport.class);
    }

    static Map<AnalyzedProperty, JsonProcessingException> serializeGetFailingProperties(
            ServerReport report) {
        Map<AnalyzedProperty, JsonProcessingException> allFailing = new HashMap<>();
        while (true) {
            try {
                String json = serialize(report);
                Assertions.assertFalse(
                        json.isEmpty(), "Report should not serialize to empty string");
                return allFailing;
            } catch (InvalidDefinitionException e) {
                var references = e.getPath();
                assert references.get(0).getFieldName().equals("results") : e;
                var failingProperty = TlsAnalyzedProperty.valueOf(references.get(1).getFieldName());
                report.removeResult(failingProperty);
                report.getScoreReport().getInfluencers().remove(failingProperty);
                assert !allFailing.containsKey(failingProperty);
                allFailing.put(failingProperty, e);
            } catch (JsonProcessingException e) {
                StringBuilder message = new StringBuilder();
                message.append(
                        "JsonProcessingException occured while trying to serialize report. Already determined the following failing properties: ");
                boolean first = true;
                for (AnalyzedProperty failingProperty : allFailing.keySet()) {
                    if (first) {
                        first = false;
                    } else {
                        message.append(", ");
                    }
                    message.append(failingProperty.getName());
                }
                throw new RuntimeException(message.toString(), e);
            }
        }
    }

    static void serializeCheckingFailingProperties(ServerReport report) {
        Map<AnalyzedProperty, JsonProcessingException> failingProperties =
                serializeGetFailingProperties(report);
        if (!failingProperties.isEmpty()) {
            LOGGER.error("Failing properties:");
            for (var entry : failingProperties.entrySet()) {
                LOGGER.error(
                        "Property {} failed to serialize: {}",
                        entry.getKey().getName(),
                        entry.getValue());
            }
        }
        Assertions.assertTrue(
                failingProperties.isEmpty(), "At least one Property failed to serialize");
    }

    @Test
    void emptyReportSerializes() throws JsonProcessingException {
        ServerReport report = new ServerReport();
        serializeCheckingFailingProperties(report);
    }

    // FIXME: deserialization does not work
    // @Test
    void emptyReportDeserializes() throws JsonProcessingException {
        ServerReport report = new ServerReport();
        ServerReport report2 = deserialize(serialize(report));
        Assertions.assertEquals(report, report2);
    }
}
