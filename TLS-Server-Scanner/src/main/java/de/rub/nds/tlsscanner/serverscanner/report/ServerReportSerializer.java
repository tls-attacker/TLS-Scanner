/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerReportSerializer {

    private static final Logger LOGGER = LogManager.getLogger();

    private ServerReportSerializer() {
        throw new IllegalStateException("Utility class");
    }

    public static void serialize(File outputFile, ServerReport scanReport) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            for (Module modules : ServerReport.getSerializerModules()) {
                mapper.registerModule(modules);
            }
            mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
            mapper.configOverride(BigDecimal.class)
                    .setFormat(JsonFormat.Value.forShape(JsonFormat.Shape.STRING));
            mapper.writeValue(outputFile, scanReport);
        } catch (IOException ex) {
            LOGGER.error(ex);
        }
    }
}
