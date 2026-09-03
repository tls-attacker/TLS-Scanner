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
import de.rub.nds.protocol.exception.ConfigurationException;
import de.rub.nds.scanner.core.config.ProbeTypeCatalog;
import de.rub.nds.scanner.core.probe.ProbeType;
import de.rub.nds.scanner.core.report.AnsiColor;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsscanner.core.constants.QuicProbeType;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.report.DefaultPrintingScheme;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.execution.TlsServerScanner;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReportPrinter;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;

public class Main {

    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) throws IOException {
        // -help and -listProbes need to work without also satisfying required parameters like
        // -connect, so they are handled before JCommander's validating parse() call.
        List<String> argList = Arrays.asList(args);
        ServerScannerConfig config = new ServerScannerConfig(new GeneralDelegate());
        JCommander commander = new JCommander(config);
        if (argList.contains("-h") || argList.contains("-help")) {
            commander.usage();
            return;
        }
        if (argList.contains("-listProbes")) {
            System.out.println(
                    ProbeTypeCatalog.toProfileProbesJson(
                            List.<Class<? extends ProbeType>>of(
                                    TlsProbeType.class, QuicProbeType.class)));
            return;
        }
        try {
            commander.parse(args);
            System.setProperty("debugMode", String.valueOf(config.getGeneralDelegate().isDebug()));
            Configurator.reconfigure();
            // Cmd was parsable
            try (TlsServerScanner scanner = new TlsServerScanner(config)) {
                long time = System.currentTimeMillis();
                LOGGER.info(
                        "Performing scan with scan detail set to "
                                + config.getExecutorConfig().getScanDetail());
                ServerReport report = scanner.scan();
                if (report.getIsHandshaking()) {
                    LOGGER.info(
                            AnsiColor.RESET.getCode()
                                    + "Scanned in: "
                                    + ((System.currentTimeMillis() - time) / 1000)
                                    + "s\n"
                                    + new ServerReportPrinter(
                                                    report,
                                                    config.getExecutorConfig().getReportDetail(),
                                                    DefaultPrintingScheme
                                                            .getDefaultPrintingScheme(),
                                                    !config.getExecutorConfig().isNoColor())
                                            .getFullReport());
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
