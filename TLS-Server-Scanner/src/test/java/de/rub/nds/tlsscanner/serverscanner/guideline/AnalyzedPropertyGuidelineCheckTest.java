/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsscanner.serverscanner.guideline.checks.AnalyzedPropertyGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import org.checkerframework.checker.units.qual.A;
import org.junit.Assert;
import org.junit.Test;

public class AnalyzedPropertyGuidelineCheckTest {

    @Test
    public void testPositive() {
        SiteReport report = new SiteReport("test");
        report.putResult(AnalyzedProperty.SUPPORTS_TLS13_PSK, true);

        AnalyzedPropertyGuidelineCheck check = new AnalyzedPropertyGuidelineCheck();
        check.setProperty(AnalyzedProperty.SUPPORTS_TLS13_PSK);
        check.setResult(TestResult.TRUE);

        GuidelineCheckResult result = new GuidelineCheckResult("test");

        check.evaluate(report, result);

        Assert.assertEquals(GuidelineCheckStatus.PASSED, result.getStatus());
    }

    @Test
    public void testNegative() {
        SiteReport report = new SiteReport("test");
        report.putResult(AnalyzedProperty.SUPPORTS_TLS13_PSK, true);

        AnalyzedPropertyGuidelineCheck check = new AnalyzedPropertyGuidelineCheck();
        check.setProperty(AnalyzedProperty.SUPPORTS_TLS13_PSK);
        check.setResult(TestResult.FALSE);

        GuidelineCheckResult result = new GuidelineCheckResult("test");

        check.evaluate(report, result);

        Assert.assertEquals(GuidelineCheckStatus.FAILED, result.getStatus());
    }

    @Test
    public void testUncertain() {
        SiteReport report = new SiteReport("test");

        AnalyzedPropertyGuidelineCheck check = new AnalyzedPropertyGuidelineCheck();
        check.setProperty(AnalyzedProperty.SUPPORTS_TLS13_PSK);
        check.setResult(TestResult.FALSE);

        GuidelineCheckResult result = new GuidelineCheckResult("test");

        check.evaluate(report, result);

        Assert.assertEquals(GuidelineCheckStatus.UNCERTAIN, result.getStatus());
    }
}
