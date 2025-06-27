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

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

public class HashAlgorithmsGuidelineCheckResultTest {

    @Test
    public void testRecommendedAlgorithmsField() {
        List<HashAlgorithm> recommendedAlgorithms =
                Arrays.asList(HashAlgorithm.SHA256, HashAlgorithm.SHA384);
        Set<HashAlgorithm> notRecommendedAlgorithms =
                new HashSet<>(Collections.singletonList(HashAlgorithm.SHA1));

        HashAlgorithmsGuidelineCheckResult result =
                new HashAlgorithmsGuidelineCheckResult(
                        "Test Check",
                        GuidelineAdherence.VIOLATED,
                        notRecommendedAlgorithms,
                        recommendedAlgorithms);

        assertEquals(recommendedAlgorithms, result.getRecommendedAlgorithms());
        assertEquals(notRecommendedAlgorithms, result.getNotRecommendedAlgorithms());
        assertEquals(GuidelineAdherence.VIOLATED, result.getAdherence());
    }

    @Test
    public void testBackwardCompatibility() {
        Set<HashAlgorithm> notRecommendedAlgorithms =
                new HashSet<>(Collections.singletonList(HashAlgorithm.SHA1));

        HashAlgorithmsGuidelineCheckResult result =
                new HashAlgorithmsGuidelineCheckResult(
                        "Test Check", GuidelineAdherence.VIOLATED, notRecommendedAlgorithms);

        assertNull(result.getRecommendedAlgorithms());
        assertEquals(notRecommendedAlgorithms, result.getNotRecommendedAlgorithms());
        assertEquals(GuidelineAdherence.VIOLATED, result.getAdherence());
    }
}
