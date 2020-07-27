/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.AnsiColor;
import de.rub.nds.tlsscanner.serverscanner.leak.InformationLeakReport;
import de.rub.nds.tlsscanner.serverscanner.leak.InformationLeakTest;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class Main {

    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) throws IOException {
        ScannerConfig config = new ScannerConfig(new GeneralDelegate());
        JCommander commander = new JCommander(config);
        try {
            commander.parse(args);
            if (config.getGeneralDelegate().isHelp()) {
                commander.usage();
                return;
            }
            // Cmd was parsable
            try {
                TlsScanner scanner = new TlsScanner(config);
                long time = System.currentTimeMillis();
                LOGGER.info("Performing Scan, this may take some time...");
                SiteReport report = scanner.scan();
                LOGGER.info("Scanned in: " + ((System.currentTimeMillis() - time) / 1000) + "s\n");
                ConsoleLogger.CONSOLE.info(AnsiColor.RESET.getCode() + "Scanned in: "
                        + ((System.currentTimeMillis() - time) / 1000) + "s\n"
                        + report.getFullReport(config.getReportDetail(), !config.isNoColor()));
            } catch (ConfigurationException E) {
                LOGGER.error("Encountered a ConfigurationException aborting.", E);
            }
        } catch (ParameterException E) {
            LOGGER.error("Could not parse provided parameters", E);
            commander.usage();
        }
    }
}
