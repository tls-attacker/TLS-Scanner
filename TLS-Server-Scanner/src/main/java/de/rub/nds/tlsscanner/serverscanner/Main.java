/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.scanner.core.report.AnsiColor;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsscanner.core.report.DefaultPrintingScheme;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.execution.TlsServerScanner;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReportPrinter;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Main {

    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) throws IOException {
        ServerScannerConfig config = new ServerScannerConfig(new GeneralDelegate());
        JCommander commander = new JCommander(config);
        try {
            commander.parse(args);
            if (config.getGeneralDelegate().isHelp()) {
                commander.usage();
                return;
            }
            // Cmd was parsable
            try (TlsServerScanner scanner = new TlsServerScanner(config)) {
                long time = System.currentTimeMillis();
                LOGGER.info("Performing Scan, this may take some time...");
                ServerReport report = scanner.scan();
                LOGGER.info(
                        AnsiColor.RESET.getCode()
                                + "Scanned in: "
                                + ((System.currentTimeMillis() - time) / 1000)
                                + "s\n"
                                + new ServerReportPrinter(
                                                report,
                                                config.getExecutorConfig().getReportDetail(),
                                                DefaultPrintingScheme.getDefaultPrintingScheme(),
                                                !config.getExecutorConfig().isNoColor())
                                        .getFullReport());
            } catch (ConfigurationException e) {
                LOGGER.error("Encountered a ConfigurationException aborting.", e);
            }
        } catch (ParameterException e) {
            LOGGER.error("Could not parse provided parameters", e);
            commander.usage();
        }
    }
}
