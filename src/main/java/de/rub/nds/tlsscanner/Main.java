/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.AnsiEscapeSequence;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class Main {

    private static final Logger LOGGER = LogManager.getLogger(Main.class.getName());

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
                LOGGER.info("Scanned in:" + ((System.currentTimeMillis()-time)/1000) + "s\n");
                if(!config.getGeneralDelegate().isDebug()){
                    // ANSI escape sequences to erase the progressbar
                    ConsoleLogger.CONSOLE.info(AnsiEscapeSequence.ANSI_ONE_LINE_UP + AnsiEscapeSequence.ANSI_ERASE_LINE);
                }
                ConsoleLogger.CONSOLE.info("Scanned in: " + ((System.currentTimeMillis()-time)/1000) + "s\n" + report.getFullReport(config.getReportDetail()));
            } catch (ConfigurationException E) {
                LOGGER.info("Encountered a ConfigurationException aborting.");
                LOGGER.warn(E);
            }
        } catch (ParameterException E) {
            LOGGER.info("Could not parse provided parameters");
            LOGGER.debug(E);
            commander.usage();
        }
    }
}
