/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
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
import de.rub.nds.tlsscanner.constants.AnsiColors;
import de.rub.nds.tlsscanner.constants.AnsiEscapeSequence;
import de.rub.nds.tlsscanner.rating.PropertyRatingInfluencer;
import de.rub.nds.tlsscanner.rating.PropertyRecommendation;
import de.rub.nds.tlsscanner.rating.RatingInfluencer;
import de.rub.nds.tlsscanner.rating.ScoreReport;
import de.rub.nds.tlsscanner.rating.SiteReportRater;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.io.IOException;
import java.util.Map;
import javax.xml.bind.JAXBException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

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
                if (config.getGeneralDelegate().isDebug()) {
                    ThreadContext.put("ROUTINGKEY", "special");
                }
                TlsScanner scanner = new TlsScanner(config);
                long time = System.currentTimeMillis();
                LOGGER.info("Performing Scan, this may take some time...");
                SiteReport report = scanner.scan();
                LOGGER.info("Scanned in:" + ((System.currentTimeMillis() - time) / 1000) + "s\n");
                if (!config.getGeneralDelegate().isDebug() && !config.isNoProgressbar()) {
                    // ANSI escape sequences to erase the progressbar
                    ConsoleLogger.CONSOLE.info(AnsiEscapeSequence.ANSI_ONE_LINE_UP + AnsiEscapeSequence.ANSI_ERASE_LINE);
                }
                ConsoleLogger.CONSOLE.info(AnsiColors.ANSI_RESET+ "Scanned in: " + ((System.currentTimeMillis() - time) / 1000) + "s\n" + report.getFullReport(config.getReportDetail()));
                SiteReportRater rater = SiteReportRater.getSiteReportRater("en");
                ScoreReport scoreReport = rater.getScoreReport(report);
                ConsoleLogger.CONSOLE.info("Score: " + scoreReport.getScore());
                ConsoleLogger.CONSOLE.info("--------------------------------");
                for (Map.Entry<AnalyzedProperty, PropertyRatingInfluencer> entry : scoreReport.getInfluencers().entrySet()) {
                    PropertyRatingInfluencer influencer = entry.getValue();
                    ConsoleLogger.CONSOLE.info(entry.getKey() + ": " + influencer.getResult() + " (Score: " + influencer.getInfluence() + ")");
                }
                ConsoleLogger.CONSOLE.info("--------------------------------");
                for (Map.Entry<AnalyzedProperty, PropertyRatingInfluencer> entry : scoreReport.getInfluencers().entrySet()) {
                    PropertyRatingInfluencer influencer = entry.getValue();
                    if(influencer.hasNegativeScore()) {
                        ConsoleLogger.CONSOLE.error(entry.getKey() + ": " + influencer.getResult());
                        ConsoleLogger.CONSOLE.error("  Score: " + influencer.getInfluence());
                        ConsoleLogger.CONSOLE.error("  Score cap: " + influencer.getScoreCap());
                        PropertyRecommendation recommendation = rater.getRecommendations().getPropertyRecommendation(entry.getKey(), influencer.getResult());
                        ConsoleLogger.CONSOLE.error("  Information: " + recommendation.getInformation());
                    }
                }
            } catch (ConfigurationException | JAXBException E) {
                LOGGER.error("Encountered a ConfigurationException aborting.", E);
            }
        } catch (ParameterException E) {
            LOGGER.error("Could not parse provided parameters", E);
            commander.usage();
        }
    }
}
