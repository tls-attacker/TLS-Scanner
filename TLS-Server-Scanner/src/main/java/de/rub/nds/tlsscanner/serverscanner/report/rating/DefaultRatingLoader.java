/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report.rating;

import de.rub.nds.scanner.core.report.rating.*;
import de.rub.nds.scanner.core.report.rating.RatingInfluencersIO;
import de.rub.nds.scanner.core.report.rating.RecommendationsIO;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import jakarta.xml.bind.JAXBException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utility class for loading default rating configurations for TLS server reports. This class
 * provides functionality to load rating influencers and recommendations from XML resource files.
 */
public class DefaultRatingLoader {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * The resource location for the rating influencers XML file. This file contains the
     * configuration for how different properties influence the overall rating of a TLS server.
     */
    public static final String INFLUENCERS_RESOURCE_LOCATION = "rating/influencers.xml";

    /**
     * The default resource template path for recommendation files. Language-specific versions can
     * be loaded by appending the language code (e.g., "rating/recommendations_en.xml" for English).
     */
    public static final String DEFAULT_RECOMMENDATIONS_TEMPLATE = "rating/recommendations";

    /**
     * Creates and returns a SiteReportRater configured with rating influencers and
     * language-specific recommendations for evaluating TLS server configurations.
     *
     * @param recommendationLanguage the ISO language code for loading localized recommendations
     *     (e.g., "en" for English, "de" for German). If no language-specific file is found,
     *     defaults to English.
     * @return a configured SiteReportRater instance ready to evaluate server reports
     * @throws JAXBException if there is an error parsing the XML configuration files
     * @throws IOException if there is an error reading the resource files
     * @throws XMLStreamException if there is an error processing the XML stream
     */
    public static SiteReportRater getServerReportRater(String recommendationLanguage)
            throws JAXBException, IOException, XMLStreamException {
        ClassLoader classLoader = ServerReport.class.getClassLoader();
        InputStream in = classLoader.getResourceAsStream(INFLUENCERS_RESOURCE_LOCATION);
        RatingInfluencers ratingInfluencers =
                new RatingInfluencersIO(TlsAnalyzedProperty.class).read(in);
        String fileName = DEFAULT_RECOMMENDATIONS_TEMPLATE + "_" + recommendationLanguage + ".xml";
        URL u = classLoader.getResource(fileName);
        if (u == null) {
            LOGGER.warn(
                    "Could not find language resources \""
                            + fileName
                            + "\" for ServerReportRater. Using default (english).");
            fileName = DEFAULT_RECOMMENDATIONS_TEMPLATE + ".xml";
        }
        in = classLoader.getResourceAsStream(fileName);
        Recommendations recommendations = new RecommendationsIO(TlsAnalyzedProperty.class).read(in);

        SiteReportRater instance = new SiteReportRater(ratingInfluencers, recommendations);
        return instance;
    }
}
