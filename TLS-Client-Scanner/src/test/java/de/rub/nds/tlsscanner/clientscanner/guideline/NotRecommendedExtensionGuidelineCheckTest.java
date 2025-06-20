/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.guideline;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.clientscanner.guideline.checks.NotRecommendedExtensionGuidelineCheck;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.Collections;
import org.junit.jupiter.api.Test;

public class NotRecommendedExtensionGuidelineCheckTest {

    @Test
    public void testPositive() {
        ClientReport report = new ClientReport();
        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_EXTENSIONS,
                Collections.singletonList(ExtensionType.COOKIE));

        NotRecommendedExtensionGuidelineCheck check =
                new NotRecommendedExtensionGuidelineCheck(
                        null, null, ExtensionType.RENEGOTIATION_INFO);
        GuidelineCheckResult result = check.evaluate(report);
        assertEquals(GuidelineAdherence.ADHERED, result.getAdherence());
    }

    @Test
    public void testNegative() {
        ClientReport report = new ClientReport();
        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_EXTENSIONS,
                Collections.singletonList(ExtensionType.COOKIE));

        NotRecommendedExtensionGuidelineCheck check =
                new NotRecommendedExtensionGuidelineCheck(null, null, ExtensionType.COOKIE);
        GuidelineCheckResult result = check.evaluate(report);
        assertEquals(GuidelineAdherence.VIOLATED, result.getAdherence());
    }

    @Test
    public void testPositiveMultipleExtensions() {
        ClientReport report = new ClientReport();
        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_EXTENSIONS,
                Collections.singletonList(ExtensionType.HEARTBEAT));

        NotRecommendedExtensionGuidelineCheck check =
                new NotRecommendedExtensionGuidelineCheck(
                        null, null, ExtensionType.COOKIE, ExtensionType.RENEGOTIATION_INFO);
        GuidelineCheckResult result = check.evaluate(report);
        assertEquals(GuidelineAdherence.ADHERED, result.getAdherence());
    }

    @Test
    public void testNegativeMultipleExtensions() {
        ClientReport report = new ClientReport();
        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_EXTENSIONS,
                Collections.singletonList(ExtensionType.RENEGOTIATION_INFO));

        NotRecommendedExtensionGuidelineCheck check =
                new NotRecommendedExtensionGuidelineCheck(
                        null, null, ExtensionType.COOKIE, ExtensionType.RENEGOTIATION_INFO);
        GuidelineCheckResult result = check.evaluate(report);
        assertEquals(GuidelineAdherence.VIOLATED, result.getAdherence());
    }
}
