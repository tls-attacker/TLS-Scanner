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
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

public class SiteReportRater {

    public static String INFLUENCERS_FILE = "rating/influencers.xml";

    public static String RECOMMENDATIONS_FILE = "rating/recommendations";

    private static SiteReportRater instance;

    private RatingInfluencers influencers;

    private Recommendations recommendations;

    private SiteReportRater() {
    }

    public static SiteReportRater getSiteReportRater(String language) throws JAXBException {
        if (instance == null) {
            ClassLoader classLoader = SiteReport.class.getClassLoader();
            JAXBContext context = JAXBContext.newInstance(RatingInfluencers.class);
            Unmarshaller um = context.createUnmarshaller();
            InputStream in = classLoader.getResourceAsStream(INFLUENCERS_FILE);
            RatingInfluencers influencers = (RatingInfluencers) um.unmarshal(in);

            context = JAXBContext.newInstance(Recommendations.class);
            um = context.createUnmarshaller();
            String fileName = RECOMMENDATIONS_FILE + "_" + language + ".xml";
            URL u = classLoader.getResource(fileName);
            if (u == null) {
                fileName = RECOMMENDATIONS_FILE + ".xml";
            }
            in = classLoader.getResourceAsStream(fileName);
            Recommendations recommendations = (Recommendations) um.unmarshal(in);

            instance = new SiteReportRater();
            instance.influencers = influencers;
            instance.recommendations = recommendations;
        }

        return instance;
    }

    public ScoreReport getScoreReport(SiteReport report) {
        HashMap<AnalyzedProperty, PropertyResultRatingInfluencer> ratingInfluencers = new HashMap<>();

        HashMap<String, TestResult> resultMap = report.getResultMap();

        for (Map.Entry<String, TestResult> entry : resultMap.entrySet()) {
            AnalyzedProperty property = AnalyzedProperty.valueOf(entry.getKey());
            PropertyResultRatingInfluencer ratingInfluencer = influencers.getPropertyRatingInfluencer(property, entry.getValue());
            ratingInfluencers.put(property, ratingInfluencer);
        }

        LinkedHashMap<AnalyzedProperty, PropertyResultRatingInfluencer> sortedRatingInfluencers = ratingInfluencers.entrySet().stream().
                sorted(Entry.comparingByValue()).collect(
                        Collectors.toMap(Entry::getKey, Entry::getValue,(e1, e2) -> e1, LinkedHashMap::new));

//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_SSL_3, 200, -300, 400.0);
//        if (Objects.equals(report.getSupportsSsl3(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_TLS_1_0, 50, 0, null);
//        if (Objects.equals(report.getSupportsTls10(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_TLS_1_3, 100, 0, null);
//        if (Objects.equals(report.getSupportsTls13(), Boolean.TRUE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_PFS, 50, -200, 1500.0);
//        if (Objects.equals(report.getSupportsPfsCiphers(), Boolean.TRUE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.PREFERS_PFS, 50, 0, null);
//        if (Objects.equals(report.getPrefersPfsCiphers(), Boolean.TRUE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.ENFORCES_PFS, 100, 0, null);
//        if (Objects.equals(report.getSupportsOnlyPfsCiphers(), Boolean.TRUE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.ENFOCRES_CS_ORDERING, 50, -50, null);
//        if (Objects.equals(report.getEnforcesCipherSuiteOrdering(), Boolean.TRUE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_NULL_CIPHERS, 100, -400, 200.0);
//        if (Objects.equals(report.getSupportsNullCiphers(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_FORTEZZA, 0, -100, 800.0);
//        if (Objects.equals(report.getSupportsFortezza(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_EXPORT, 100, -500, 600.0);
//        if (Objects.equals(report.getSupportsExportCiphers(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_ANON, 100, -300, 600.0);
//        if (Objects.equals(report.getSupportsAnonCiphers(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_DES, 100, -200, 600.0);
//        if (Objects.equals(report.getSupportsDesCiphers(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_IDEA, 50, -150, 800.0);
//        if (Objects.equals(report.getSupportsIdeaCiphers(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_RC2, 50, -200, 600.0);
//        if (Objects.equals(report.getSupportsIdeaCiphers(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_RC4, 100, -200, 600.0);
//        if (Objects.equals(report.getSupportsIdeaCiphers(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_CBC, 400, 0, null);
//        if (Objects.equals(report.getSupportsBlockCiphers(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_AEAD, 200, -200, null);
//        if (Objects.equals(report.getSupportsAeadCiphers(), Boolean.TRUE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET, 100, 0, null);
//        if (Objects.equals(report.getSupportsExtendedMasterSecret(), Boolean.TRUE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC, 100, 0, null);
//        if (Objects.equals(report.getSupportsEncryptThenMacSecret(), Boolean.TRUE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_MONTOGMERY_CURVES, 100, 0, null);
//        if (report.getSupportedNamedGroups().contains(NamedGroup.ECDH_X25519) || report.getSupportedNamedGroups().contains(NamedGroup.ECDH_X448)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_SESSION_TICKETS, 100, 0, null);
//        if (Objects.equals(report.getSupportsSessionTicket(), Boolean.TRUE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION, 100, -100, null);
//        if (report.getSupportedExtensions().contains(ExtensionType.RENEGOTIATION_INFO)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_TOKENBINDING, 100, 0, null);
//        if (Objects.equals(report.getSupportsTokenbinding(), Boolean.TRUE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_TLS_COMPRESSION, 100, -400, 600.0);
//        if (Objects.equals(report.getCrimeVulnerable(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_BLEICHENBACHER, 200, -400, 600.0);
//        if (Objects.equals(report.getBleichenbacherVulnerable(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_CBC_PADDING_ORACLE, 200, -300, 600.0);
//        if (Objects.equals(report.getBleichenbacherVulnerable(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_HTTP_COMPRESSION, 0, -50, null);
//        if (Objects.equals(report.getBreachVulnerable(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE, 100, -800, 400.0);
//        if (Objects.equals(report.getInvalidCurveVulnerable(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL, 100, -200, 600.0);
//        if (Objects.equals(report.getInvalidCurveEphermaralVulnerable(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL_WITH_REUSE, 100, -200, 600.0);
//        if (Objects.equals(report.getInvalidCurveVulnerable(), Boolean.TRUE) && Objects.equals(report.getEcPubkeyReuse(), Boolean.TRUE)) {
//            negativeInfluencer.add(tempInfluencer);
//        } else {
//            positiveInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_POODLE, 100, -300, 600.0);
//        if (Objects.equals(report.getPoodleVulnerable(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_TLS_POODLE, 100, -400, 600.0);
//        if (Objects.equals(report.getPoodleVulnerable(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_SWEET_32, 100, -100, null);
//        if (Objects.equals(report.getSweet32Vulnerable(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_DROWN, 100, -400, 600.0);
//        if (Objects.equals(report.getPoodleVulnerable(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_HEARTBLEED, 100, -1000, 0.0);
//        if (Objects.equals(report.getHeartbleedVulnerable(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_EARLY_CCS, 100, -50, null);
//        if (report.getEarlyCcsVulnerable() != EarlyCcsVulnerabilityType.VULN_EXPLOITABLE && report.getEarlyCcsVulnerable() != EarlyCcsVulnerabilityType.VULN_NOT_EXPLOITABLE) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.MISSES_MAC_APPDATA_CHECKS, 100, -500, 600.0);
//        if (report.getMacCheckPatternAppData() != null && report.getMacCheckPatternAppData().getType() == CheckPatternType.CORRECT) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.MISSES_CHECKS_MAC_FINISHED_CHECKS, 50, -100, 800.0);
//        if (report.getMacCheckPatternAppData() != null && report.getMacCheckPatternFinished().getType() == CheckPatternType.CORRECT) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.MISSES_CHECKS_VERIFY_DATA_CHECKS, 50, -100, 800.0);
//        if (report.getVerifyCheckPattern() != null && report.getVerifyCheckPattern().getType() == CheckPatternType.CORRECT) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.HAS_CERTIFICATE_ISSUES, 100, -400, 500.0);
//        if (report.getCertificateChain().getCertificateIssues().isEmpty()) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_INSECURE_RENEGOTIATION, 100, -200, 800.0);
//        if (report.getCertificateChain().getCertificateIssues().isEmpty()) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_RENEGOTIATION, 100, -200, 1200.0);
//        if (Objects.equals(report.getSupportsClientSideInsecureRenegotiation(), Boolean.FALSE) && Objects.equals(report.getSupportsClientSideSecureRenegotiation(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_HSTS, 100, 0, null);
//        if (Objects.equals(report.getSupportsHsts(), Boolean.TRUE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_HPKP_REPORTING, 100, 0, null);
//        if (Objects.equals(report.getSupportsHpkpReportOnly(), Boolean.TRUE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.HAS_WEAK_RANDOMNESS, 0, -500, 400.0);
//        if (report.getRandomEvaluationResult() == RandomEvaluationResult.NO_DUPLICATES) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.REUSES_EC_PUBLICKEY, 0, -100, 1200.0);
//        if (Objects.equals(report.getEcPubkeyReuse(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.REUSES_DH_PUBLICKEY, 0, -100, 1200.0);
//        if (Objects.equals(report.getDhPubkeyReuse(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES, 100, -50, 1200.0);
//        if (Objects.equals(report.getUsesCommonDhPrimes(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_PRIME_MODULI, 0, -800, 300.0);
//        if (Objects.equals(report.getUsesNonPrimeModuli(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
//        tempInfluencer = new RatingInfluencer(AnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES, 100, -100, null);
//        if (Objects.equals(report.getUsesNonSafePrimeModuli(), Boolean.FALSE)) {
//            positiveInfluencer.add(tempInfluencer);
//        } else {
//            negativeInfluencer.add(tempInfluencer);
//        }
//
        double score = computeScore(ratingInfluencers);
        return new ScoreReport(score, sortedRatingInfluencers);
    }

    private double computeScore(HashMap<AnalyzedProperty, PropertyResultRatingInfluencer> influencers) {
        double score = 0;
        for (PropertyResultRatingInfluencer influencer : influencers.values()) {
            score += influencer.getInfluence();
        }
        for (PropertyResultRatingInfluencer influencer : influencers.values()) {
            if (influencer.getScoreCap() != 0.0 && score >= influencer.getScoreCap()) {
                score = influencer.getScoreCap();
            }
        }
        return score;
    }

    public Recommendations getRecommendations() {
        return recommendations;
    }
}
