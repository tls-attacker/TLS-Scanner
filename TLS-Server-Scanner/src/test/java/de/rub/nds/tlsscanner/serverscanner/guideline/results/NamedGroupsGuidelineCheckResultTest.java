/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class NamedGroupsGuidelineCheckResultTest {

    @Test
    void testToStringNeverReturnsNull() {
        // Test with CHECK_FAILED adherence
        NamedGroupsGuidelineCheckResult result1 =
                new NamedGroupsGuidelineCheckResult("test1", GuidelineAdherence.CHECK_FAILED);
        assertNotNull(result1.toString());
        assertTrue(result1.toString().contains("Missing information"));

        // Test with ADHERED adherence
        NamedGroupsGuidelineCheckResult result2 =
                new NamedGroupsGuidelineCheckResult("test2", GuidelineAdherence.ADHERED);
        assertNotNull(result2.toString());
        assertTrue(result2.toString().contains("Server passed"));

        // Test with not recommended groups
        Set<NamedGroup> notRecommended = new HashSet<>();
        notRecommended.add(NamedGroup.SECP224R1);
        NamedGroupsGuidelineCheckResult result3 =
                new NamedGroupsGuidelineCheckResult(
                        "test3", GuidelineAdherence.VIOLATED, notRecommended);
        assertNotNull(result3.toString());
        assertTrue(result3.toString().contains("not recommended"));

        // Test with missing required groups
        NamedGroupsGuidelineCheckResult result4 =
                new NamedGroupsGuidelineCheckResult(
                        "test4", GuidelineAdherence.VIOLATED, Arrays.asList(NamedGroup.SECP256R1));
        assertNotNull(result4.toString());
        assertTrue(result4.toString().contains("missing one of required"));

        // Test with group count
        NamedGroupsGuidelineCheckResult result5 =
                new NamedGroupsGuidelineCheckResult("test5", GuidelineAdherence.VIOLATED, 3);
        assertNotNull(result5.toString());
        assertTrue(result5.toString().contains("only supports 3 groups"));

        // Test default case - this is the case that was returning null
        NamedGroupsGuidelineCheckResult result6 =
                new NamedGroupsGuidelineCheckResult("test6", GuidelineAdherence.VIOLATED);
        assertNotNull(result6.toString());
        assertTrue(result6.toString().contains("No specific named groups information"));
    }
}
