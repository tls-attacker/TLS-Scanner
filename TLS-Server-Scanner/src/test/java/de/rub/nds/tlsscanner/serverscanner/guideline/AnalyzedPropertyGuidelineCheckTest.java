/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.AnalyzedPropertyGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import org.junit.jupiter.api.Test;

public class AnalyzedPropertyGuidelineCheckTest {

    @Test
    public void testPositive() {
        ServerReport report = new ServerReport("test", 443);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK, true);

        AnalyzedPropertyGuidelineCheck check =
                new AnalyzedPropertyGuidelineCheck(
                        null, null, TlsAnalyzedProperty.SUPPORTS_TLS13_PSK, TestResults.TRUE);

        GuidelineCheckResult result = check.evaluate(report);

        assertEquals(GuidelineAdherence.ADHERED, result.getAdherence());
    }

    @Test
    public void testNegative() {
        ServerReport report = new ServerReport("test", 443);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK, true);

        AnalyzedPropertyGuidelineCheck check =
                new AnalyzedPropertyGuidelineCheck(
                        null, null, TlsAnalyzedProperty.SUPPORTS_TLS13_PSK, TestResults.FALSE);

        GuidelineCheckResult result = check.evaluate(report);

        assertEquals(GuidelineAdherence.VIOLATED, result.getAdherence());
    }

    @Test
    public void testUncertain() {
        ServerReport report = new ServerReport("test", 443);

        AnalyzedPropertyGuidelineCheck check =
                new AnalyzedPropertyGuidelineCheck(
                        null, null, TlsAnalyzedProperty.SUPPORTS_TLS13_PSK, TestResults.FALSE);

        GuidelineCheckResult result = check.evaluate(report);

        assertEquals(GuidelineAdherence.CHECK_FAILED, result.getAdherence());
    }
}
