/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsscanner.serverscanner.rating;

import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.io.InputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.LinkedHashMap;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SiteReportRater {

    private static final Logger LOGGER = LogManager.getLogger();

    private static String INFLUENCERS_RESOURCE_LOCATION = "rating/influencers.xml";

    private static String RECOMMENDATIONS_RESOURCE_LOCATION = "rating/recommendations";

    private static HashMap<String, Recommendations> recommendationsMap;

    private static RatingInfluencers influencers;

    private SiteReportRater() {
    }

    /**
     * Returns a generic SiteReportRater Language of the recommendations. If no language file can be found for selected
     * language a default recommendation file in english is returned
     *
     * @return A generated SiteReportRater
     * @throws JAXBException
     */
    public static SiteReportRater getSiteReportRater() throws JAXBException {
        // only create a SiteReportRater, if the influencers can be parsed and accessed. Do not create a SiteReportRater
        // and forward the exception if the influencers cannot be parsed.
        if (influencers == null) {
            parseRatingInfluencers();
        }

        SiteReportRater instance = new SiteReportRater();
        return instance;

    }

    private static void parseRatingInfluencers() throws JAXBException {

        ClassLoader classLoader = SiteReport.class.getClassLoader();
        JAXBContext context = JAXBContext.newInstance(RatingInfluencers.class);
        Unmarshaller um = context.createUnmarshaller();
        InputStream in = classLoader.getResourceAsStream(INFLUENCERS_RESOURCE_LOCATION);
        influencers = (RatingInfluencers) um.unmarshal(in);

    }

    public static RatingInfluencers getRatingInfluencers() throws JAXBException {
        if (influencers == null) {
            parseRatingInfluencers();
        }

        return influencers;
    }

    public static Recommendations getRecommendations(String recommendationLanguage) throws JAXBException {

        if (recommendationsMap == null) {
            recommendationsMap = new HashMap<>();
        }

        // only parse each recommendation xml once for every language
        if (!recommendationsMap.containsKey(recommendationLanguage)) {
            ClassLoader classLoader = SiteReport.class.getClassLoader();
            JAXBContext context = JAXBContext.newInstance(Recommendations.class);
            Unmarshaller um = context.createUnmarshaller();
            String fileName = RECOMMENDATIONS_RESOURCE_LOCATION + "_" + recommendationLanguage + ".xml";
            URL u = classLoader.getResource(fileName);
            if (u == null) {
                LOGGER.warn("Could not find language resources \"" + fileName
                    + "\" for SiteReportRater. Using default (english).");
                fileName = RECOMMENDATIONS_RESOURCE_LOCATION + ".xml";
            }
            InputStream in = classLoader.getResourceAsStream(fileName);
            recommendationsMap.put(recommendationLanguage, (Recommendations) um.unmarshal(in));
        }

        return recommendationsMap.get(recommendationLanguage);
    }

    public ScoreReport getScoreReport(HashMap<String, TestResult> resultMap) {
        LinkedHashMap<AnalyzedProperty, PropertyResultRatingInfluencer> ratingInfluencers = new LinkedHashMap<>();

        for (RatingInfluencer ratingInfluencer : influencers.getRatingInfluencers()) {
            TestResult result = resultMap.get(ratingInfluencer.getAnalyzedProperty().toString());
            if (result != null) {
                PropertyResultRatingInfluencer propertyRatingInfluencer =
                    ratingInfluencer.getPropertyRatingInfluencer(result);
                ratingInfluencers.put(ratingInfluencer.getAnalyzedProperty(), propertyRatingInfluencer);
            }
        }

        int score = computeScore(ratingInfluencers);
        return new ScoreReport(score, ratingInfluencers);

    }

    private int computeScore(HashMap<AnalyzedProperty, PropertyResultRatingInfluencer> influencers) {
        int score = 0;
        for (PropertyResultRatingInfluencer influencer : influencers.values()) {
            if (influencer.getInfluence() != null) {
                score += influencer.getInfluence();
            } else {
                LOGGER.warn("Influencer has 'null' influence");
            }
        }
        for (PropertyResultRatingInfluencer influencer : influencers.values()) {
            if (influencer.getScoreCap() != null && score >= influencer.getScoreCap()) {
                score = influencer.getScoreCap();
            }
        }
        return score;
    }
}
