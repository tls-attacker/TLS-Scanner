/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.rating;

import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.io.InputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.LinkedHashMap;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

public class SiteReportRater {

    private static String INFLUENCERS_RESOURCE_LOCATION = "rating/influencers.xml";

    private static String RECOMMENDATIONS_RESOURCE_LOCATION = "rating/recommendations";

    private RatingInfluencers influencers;

    private Recommendations recommendations;

    private SiteReportRater(RatingInfluencers influencers, Recommendations recommendations) {
        this.influencers = influencers;
        this.recommendations = recommendations;
    }

    private SiteReportRater() {
    }

    /**
     * Returns a generic SiteReportRater
     *
     * @param recommendationLanguage Language of the recommendations. If no
     * language file can be found for selected language a default recommendation
     * file in english is returned
     * @return
     * @throws JAXBException
     */
    public static SiteReportRater getSiteReportRater(String recommendationLanguage) throws JAXBException {
        ClassLoader classLoader = SiteReport.class.getClassLoader();
        JAXBContext context = JAXBContext.newInstance(RatingInfluencers.class);
        Unmarshaller um = context.createUnmarshaller();
        InputStream in = classLoader.getResourceAsStream(INFLUENCERS_RESOURCE_LOCATION);
        RatingInfluencers influencers = (RatingInfluencers) um.unmarshal(in);

        context = JAXBContext.newInstance(Recommendations.class);
        um = context.createUnmarshaller();
        String fileName = RECOMMENDATIONS_RESOURCE_LOCATION + "_" + recommendationLanguage + ".xml";
        URL u = classLoader.getResource(fileName);
        if (u == null) {
            fileName = RECOMMENDATIONS_RESOURCE_LOCATION + ".xml";
        }
        in = classLoader.getResourceAsStream(fileName);
        Recommendations recommendations = (Recommendations) um.unmarshal(in);

        SiteReportRater instance = new SiteReportRater(influencers, recommendations);
        return instance;
    }

    public ScoreReport getScoreReport(HashMap<String, TestResult> resultMap) {
        LinkedHashMap<AnalyzedProperty, PropertyResultRatingInfluencer> ratingInfluencers = new LinkedHashMap<>();

        for (RatingInfluencer ratingInfluencer : influencers.getRatingInfluencers()) {
            TestResult result = resultMap.get(ratingInfluencer.getAnalyzedProperty().toString());
            if (result != null) {
                PropertyResultRatingInfluencer propertyRatingInfluencer = ratingInfluencer.getPropertyRatingInfluencer(result);
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
            }
        }
        for (PropertyResultRatingInfluencer influencer : influencers.values()) {
            if (influencer.getScoreCap() != null && score >= influencer.getScoreCap()) {
                score = influencer.getScoreCap();
            }
        }
        return score;
    }

    public Recommendations getRecommendations() {
        return recommendations;
    }

    public RatingInfluencers getRatingInfluencers() {
        return influencers;
    }
}
