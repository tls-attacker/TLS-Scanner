/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.report;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.ByteArraySerializer;
import de.rub.nds.scanner.core.report.ScanReport;
import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import org.apache.logging.log4j.LogManager;

public class ClientReportSerializer {

    private static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger();

    public static void serialize(File outputFile, ScanReport scanReport) {
        try {
            ObjectMapper mapper = new ObjectMapper();

            SimpleModule module = new SimpleModule();
            module.addSerializer(new ByteArraySerializer());

            mapper.registerModule(module);
            mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
            mapper.configOverride(BigDecimal.class).setFormat(JsonFormat.Value.forShape(JsonFormat.Shape.STRING));
            mapper.writeValue(outputFile, scanReport);
        } catch (IOException ex) {
            LOGGER.error(ex);
        }
    }
}
