/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Serializer for ServerReport objects using the ServerReportJsonMapper. This class is maintained
 * for backward compatibility. New code should use ServerReportJsonMapper directly.
 */
@Deprecated
public class ServerReportSerializer {

    private static final Logger LOGGER = LogManager.getLogger();

    private ServerReportSerializer() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * Serializes a ServerReport to a file.
     *
     * @param outputFile the file to write the report to
     * @param scanReport the report to serialize
     */
    public static void serialize(File outputFile, ServerReport scanReport) {
        try {
            if (!outputFile.exists()) {
                outputFile.createNewFile();
            }
            serialize(new FileOutputStream(outputFile), scanReport);
        } catch (IOException ex) {
            LOGGER.error("Could not write report to file", ex);
        }
    }

    /**
     * Serializes a ServerReport to an output stream. Uses the ServerReportJsonMapper for actual
     * serialization.
     *
     * @param stream the stream to write the report to
     * @param scanReport the report to serialize
     */
    public static void serialize(OutputStream stream, ServerReport scanReport) {
        try {
            ServerReportJsonMapper mapper = new ServerReportJsonMapper();
            String jsonString = mapper.toJsonString(scanReport);
            stream.write(jsonString.getBytes());
        } catch (IOException ex) {
            LOGGER.error("Error serializing ServerReport to JSON", ex);
        }
    }
}
