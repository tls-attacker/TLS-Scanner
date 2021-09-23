/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.rating;

import de.rub.nds.scanner.core.report.rating.RatingInfluencers;
import de.rub.nds.scanner.core.report.rating.Recommendations;
import de.rub.nds.scanner.core.report.rating.SiteReportRater;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DefaultRatingLoader {

    private static Logger LOGGER = LogManager.getLogger();

    public static String INFLUENCERS_RESOURCE_LOCATION = "rating/influencers.xml";

    /**
     * The default Config file to load.
     */
    public static final String DEFAULT_RECOMMENDATIONS_TEMPLATE = "rating/recommendations";

    /**
     * Returns a generic SiteReportRater
     *
     * @param  recommendationLanguage
     *                                             Language of the recommendations. If no language file can be found for
     *                                             selected language a default recommendation file in english is
     *                                             returned
     * @return                                     A generated SiteReportRater
     * @throws JAXBException
     * @throws java.io.IOException
     * @throws javax.xml.stream.XMLStreamException
     */
    public static SiteReportRater getServerReportRater(String recommendationLanguage)
        throws JAXBException, IOException, XMLStreamException {
        ClassLoader classLoader = ServerReport.class.getClassLoader();
        InputStream in = classLoader.getResourceAsStream(INFLUENCERS_RESOURCE_LOCATION);
        RatingInfluencers ratingInfluencers = RatingInfluencersIO.read(in);
        String fileName = DEFAULT_RECOMMENDATIONS_TEMPLATE + "_" + recommendationLanguage + ".xml";
        URL u = classLoader.getResource(fileName);
        if (u == null) {
            LOGGER.warn("Could not find language resources \"" + fileName
                + "\" for ServerReportRater. Using default (english).");
            fileName = DEFAULT_RECOMMENDATIONS_TEMPLATE + ".xml";
        }
        in = classLoader.getResourceAsStream(fileName);
        Recommendations recommendations = RecommendationsIO.read(in);

        SiteReportRater instance = new SiteReportRater(ratingInfluencers, recommendations);
        return instance;
    }
}
