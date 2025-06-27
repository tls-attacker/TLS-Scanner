/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

public class CipherSuiteGuidelineCheckResultTest {

    @Test
    public void testRecommendedSuitesField() {
        List<CipherSuite> recommendedSuites =
                Arrays.asList(
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        List<CipherSuite> notRecommendedSuites =
                Collections.singletonList(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);

        CipherSuiteGuidelineCheckResult result =
                new CipherSuiteGuidelineCheckResult(
                        "Test Check",
                        GuidelineAdherence.VIOLATED,
                        notRecommendedSuites,
                        recommendedSuites);

        assertEquals(recommendedSuites, result.getRecommendedSuites());
        assertEquals(notRecommendedSuites, result.getNotRecommendedSuites());
        assertEquals(GuidelineAdherence.VIOLATED, result.getAdherence());
    }

    @Test
    public void testBackwardCompatibility() {
        List<CipherSuite> notRecommendedSuites =
                Collections.singletonList(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);

        CipherSuiteGuidelineCheckResult result =
                new CipherSuiteGuidelineCheckResult(
                        "Test Check", GuidelineAdherence.VIOLATED, notRecommendedSuites);

        assertNull(result.getRecommendedSuites());
        assertEquals(notRecommendedSuites, result.getNotRecommendedSuites());
        assertEquals(GuidelineAdherence.VIOLATED, result.getAdherence());
    }
}
