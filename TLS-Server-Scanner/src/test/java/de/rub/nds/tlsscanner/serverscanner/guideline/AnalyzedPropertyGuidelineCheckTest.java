/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.AnalyzedPropertyGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import org.junit.Assert;
import org.junit.Test;

public class AnalyzedPropertyGuidelineCheckTest {

    @Test
    public void testPositive() {
        ServerReport report = new ServerReport("test", 443);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK, true);

        AnalyzedPropertyGuidelineCheck check =
            new AnalyzedPropertyGuidelineCheck(null, null, TlsAnalyzedProperty.SUPPORTS_TLS13_PSK, TestResult.TRUE);

        GuidelineCheckResult result = check.evaluate(report);

        Assert.assertEquals(TestResult.TRUE, result.getResult());
    }

    @Test
    public void testNegative() {
        ServerReport report = new ServerReport("test", 443);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK, true);

        AnalyzedPropertyGuidelineCheck check =
            new AnalyzedPropertyGuidelineCheck(null, null, TlsAnalyzedProperty.SUPPORTS_TLS13_PSK, TestResult.FALSE);

        GuidelineCheckResult result = check.evaluate(report);

        Assert.assertEquals(TestResult.FALSE, result.getResult());
    }

    @Test
    public void testUncertain() {
        ServerReport report = new ServerReport("test", 443);

        AnalyzedPropertyGuidelineCheck check =
            new AnalyzedPropertyGuidelineCheck(null, null, TlsAnalyzedProperty.SUPPORTS_TLS13_PSK, TestResult.FALSE);

        GuidelineCheckResult result = check.evaluate(report);

        Assert.assertEquals(TestResult.NOT_TESTED_YET, result.getResult());
    }
}
