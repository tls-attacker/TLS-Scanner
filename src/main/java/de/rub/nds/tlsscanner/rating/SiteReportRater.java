/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.rating;

import de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.constants.CheckPatternType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.statistics.RandomEvaluationResult;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

public class SiteReportRater {

    public SiteReportRater() {
    }

    public ScoreReport getScoreReport(SiteReport report) {
        List<Influencer> positiveInfluencer = new LinkedList<>();
        List<Influencer> negativeInfluencer = new LinkedList<>();

        Influencer tempInfluencer = new Influencer(AnalyzedProperty.SSL_2, 200, -500, 200.0);
        if (Objects.equals(report.getSupportsSsl2(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.SSL_3, 200, -300, 400.0);
        if (Objects.equals(report.getSupportsSsl3(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.TLS_1_0, 50, 0, null);
        if (Objects.equals(report.getSupportsTls10(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.TLS_1_3, 100, 0, null);
        if (Objects.equals(report.getSupportsTls13(), Boolean.TRUE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.SUPPORT_PFS, 50, -200, 1500.0);
        if (Objects.equals(report.getSupportsPfsCiphers(), Boolean.TRUE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.PREFER_PFS, 50, 0, null);
        if (Objects.equals(report.getPrefersPfsCiphers(), Boolean.TRUE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.ENFORCE_PFS, 100, 0, null);
        if (Objects.equals(report.getSupportsOnlyPfsCiphers(), Boolean.TRUE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.ENFOCRE_CS_ORDERING, 50, -50, null);
        if (Objects.equals(report.getEnforcesCipherSuiteOrdering(), Boolean.TRUE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.NULL_CIPHERS, 100, -400, 200.0);
        if (Objects.equals(report.getSupportsNullCiphers(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.FORTEZZA, 0, -100, 800.0);
        if (Objects.equals(report.getSupportsFortezza(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.EXPORT, 100, -500, 600.0);
        if (Objects.equals(report.getSupportsExportCiphers(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.ANON, 100, -300, 600.0);
        if (Objects.equals(report.getSupportsAnonCiphers(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.DES, 100, -200, 600.0);
        if (Objects.equals(report.getSupportsDesCiphers(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.IDEA, 50, -150, 800.0);
        if (Objects.equals(report.getSupportsIdeaCiphers(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.RC2, 50, -200, 600.0);
        if (Objects.equals(report.getSupportsIdeaCiphers(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.RC4, 100, -200, 600.0);
        if (Objects.equals(report.getSupportsIdeaCiphers(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.CBC, 400, 0, null);
        if (Objects.equals(report.getSupportsBlockCiphers(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.SUPPORT_AEAD, 200, -200, null);
        if (Objects.equals(report.getSupportsAeadCiphers(), Boolean.TRUE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.SUPPORT_EXTENDED_MASTER_SECRET, 100, 0, null);
        if (Objects.equals(report.getSupportsExtendedMasterSecret(), Boolean.TRUE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.SUPPORT_ENCRYPT_THEN_MAC, 100, 0, null);
        if (Objects.equals(report.getSupportsEncryptThenMacSecret(), Boolean.TRUE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.SUPPORT_MONTOGMERY_CURVES, 100, 0, null);
        if (report.getSupportedNamedGroups().contains(NamedGroup.ECDH_X25519) || report.getSupportedNamedGroups().contains(NamedGroup.ECDH_X448)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.SUPPORT_SESSION_TICKETS, 100, 0, null);
        if (Objects.equals(report.getSupportsSessionTicket(), Boolean.TRUE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.SUPPORT_SECURE_RENEGOTIATION_EXTENSION, 100, -100, null);
        if (report.getSupportedExtensions().contains(ExtensionType.RENEGOTIATION_INFO)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.SUPPORT_TOKENBINDING, 100, 0, null);
        if (Objects.equals(report.getSupportsTokenbinding(), Boolean.TRUE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.TLS_COMPRESSION, 100, -400, 600.0);
        if (Objects.equals(report.getCrimeVulnerable(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.BLEICHENBACHER, 200, -400, 600.0);
        if (Objects.equals(report.getBleichenbacherVulnerable(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.CBC_PADDING_ORACLE, 200, -300, 600.0);
        if (Objects.equals(report.getBleichenbacherVulnerable(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.HTTP_COMPRESSION, 0, -50, null);
        if (Objects.equals(report.getBreachVulnerable(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.INVALID_CURVE, 100, -800, 400.0);
        if (Objects.equals(report.getInvalidCurveVulnerable(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.INVALID_CURVE_EPHEMERAL, 100, -200, 600.0);
        if (Objects.equals(report.getInvalidCurveEphermaralVulnerable(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.INVALID_CURVE_EPHEMERAL_WITH_REUSE, 100, -200, 600.0);
        if (Objects.equals(report.getInvalidCurveVulnerable(), Boolean.TRUE) && Objects.equals(report.getEcPubkeyReuse(), Boolean.TRUE)) {
            negativeInfluencer.add(tempInfluencer);
        } else {
            positiveInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.POODLE, 100, -300, 600.0);
        if (Objects.equals(report.getPoodleVulnerable(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.TLS_POODLE, 100, -400, 600.0);
        if (Objects.equals(report.getPoodleVulnerable(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.SHORT_64_BIT_CIPHERSUITE, 100, -100, null);
        if (Objects.equals(report.getSweet32Vulnerable(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.DROWN, 100, -400, 600.0);
        if (Objects.equals(report.getPoodleVulnerable(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.HEARTBLEED, 100, -1000, 0.0);
        if (Objects.equals(report.getHeartbleedVulnerable(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.EARLY_CCS, 100, -50, null);
        if (report.getEarlyCcsVulnerable() != EarlyCcsVulnerabilityType.VULN_EXPLOITABLE && report.getEarlyCcsVulnerable() != EarlyCcsVulnerabilityType.VULN_NOT_EXPLOITABLE) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.MISSING_CHECKS_MAC_APPDATA, 100, -500, 600.0);
        if (report.getMacCheckPatternAppData() != null && report.getMacCheckPatternAppData().getType() == CheckPatternType.CORRECT) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.MISSING_CHECKS_MAC_FINISHED, 50, -100, 800.0);
        if (report.getMacCheckPatternAppData() != null && report.getMacCheckPatternFinished().getType() == CheckPatternType.CORRECT) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.MISSING_CHECKS_VERIFY_DATA, 50, -100, 800.0);
        if (report.getVerifyCheckPattern() != null && report.getVerifyCheckPattern().getType() == CheckPatternType.CORRECT) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.CERTIFICATE_ISSUES, 100, -400, 500.0);
        if (report.getCertificateChain().getCertificateIssues().isEmpty()) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.INSECURE_RENEGOTIATION, 100, -200, 800.0);
        if (report.getCertificateChain().getCertificateIssues().isEmpty()) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.RENEGOTIATION, 100, -200, 1200.0);
        if (Objects.equals(report.getSupportsClientSideInsecureRenegotiation(), Boolean.FALSE) && Objects.equals(report.getSupportsClientSideSecureRenegotiation(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.SUPPORT_HSTS, 100, 0, null);
        if (Objects.equals(report.getSupportsHsts(), Boolean.TRUE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.SUPPORT_HPKP_REPORTING, 100, 0, null);
        if (Objects.equals(report.getSupportsHpkpReportOnly(), Boolean.TRUE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.WEAK_RANDOMNESS, 0, -500, 400.0);
        if (report.getRandomEvaluationResult() == RandomEvaluationResult.NO_DUPLICATES) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.EC_PUBLICKEY_REUSE, 0, -100, 1200.0);
        if (Objects.equals(report.getEcPubkeyReuse(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.DH_PUBLICKEY_REUSE, 0, -100, 1200.0);
        if (Objects.equals(report.getDhPubkeyReuse(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.COMMON_DH_PRIMES, 100, -50, 1200.0);
        if (Objects.equals(report.getUsesCommonDhPrimes(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.SUPPORT_PRIME_MODULI, 0, -800, 300.0);
        if (Objects.equals(report.getUsesNonPrimeModuli(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        tempInfluencer = new Influencer(AnalyzedProperty.COMMON_DH_PRIMES, 100, -100, null);
        if (Objects.equals(report.getUsesNonSafePrimeModuli(), Boolean.FALSE)) {
            positiveInfluencer.add(tempInfluencer);
        } else {
            negativeInfluencer.add(tempInfluencer);
        }

        double score = 0;
        for (Influencer influencer : positiveInfluencer) {
            score += influencer.getInfluence();
        }
        for (Influencer influencer : negativeInfluencer) {
            score += influencer.getNegativeInfluence();
        }
        for (Influencer influencer : negativeInfluencer) {
            if (influencer.getScoreCap() != null && score >= influencer.getScoreCap()) {
                score = influencer.getScoreCap();
            }
        }
        return new ScoreReport(score, positiveInfluencer, negativeInfluencer);
    }
}
