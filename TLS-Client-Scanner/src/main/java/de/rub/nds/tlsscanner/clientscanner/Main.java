/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.scanner.core.report.AnsiColor;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.execution.TlsClientScanner;
import de.rub.nds.tlsscanner.clientscanner.report.ClientContainerReportCreator;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReportSerializer;
import java.io.File;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Main {

    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) throws IOException {
        ClientScannerConfig config = new ClientScannerConfig(new GeneralDelegate());
        JCommander commander = new JCommander(config);
        try {
            commander.parse(args);
            if (config.getGeneralDelegate().isHelp()) {
                commander.usage();
                return;
            }
            // Cmd was parsable
            try (TlsClientScanner scanner = new TlsClientScanner(config)) {
                long time = System.currentTimeMillis();
                LOGGER.info("Performing Scan, this may take some time...");
                ClientReport report = scanner.scan();

                // TODO: Implement ClientReportPrinter and use them.
                StringBuilder builder = new StringBuilder();
                new ClientContainerReportCreator(config.getExecutorConfig().getReportDetail())
                        .createReport(report)
                        .print(builder, 0, !config.getExecutorConfig().isNoColor());

                LOGGER.info(
                        AnsiColor.RESET.getCode()
                                + "Scanned in: "
                                + ((System.currentTimeMillis() - time) / 1000)
                                + "s\n"
                                + builder);
                if (config.getExecutorConfig().isWriteReportToFile()) {
                    File outputFile = new File(config.getExecutorConfig().getOutputFile());
                    ClientReportSerializer.serialize(outputFile, report);
                }
            } catch (ConfigurationException e) {
                LOGGER.error("Encountered a ConfigurationException aborting.", e);
            }
        } catch (ParameterException e) {
            LOGGER.error("Could not parse provided parameters", e);
            commander.usage();
        }
    }
}
