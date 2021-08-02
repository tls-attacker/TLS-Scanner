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
import org.junit.Assert;
import org.junit.Test;

public class ConditionalGuidelineCheckTest {

    @Test
    public void testPositive() {
        SiteReport report = new SiteReport("test");
        report.putResult(AnalyzedProperty.SUPPORTS_TLS13_PSK, false);
        report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3, true);

        AnalyzedPropertyGuidelineCheck check = new AnalyzedPropertyGuidelineCheck();
        check.setProperty(AnalyzedProperty.SUPPORTS_TLS13_PSK);
        check.setResult(TestResult.TRUE);

        GuidelineCheckCondition condition =
            new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.TRUE);
        check.setCondition(condition);

        GuidelineCheckResult result = new GuidelineCheckResult("test");

        if (check.passesCondition(report)) {
            check.evaluate(report, result);
        }

        Assert.assertEquals(GuidelineCheckStatus.FAILED, result.getStatus());
    }

    @Test
    public void testNegative() {
        SiteReport report = new SiteReport("test");
        report.putResult(AnalyzedProperty.SUPPORTS_TLS13_PSK, false);
        report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3, false);

        AnalyzedPropertyGuidelineCheck check = new AnalyzedPropertyGuidelineCheck();
        check.setProperty(AnalyzedProperty.SUPPORTS_TLS13_PSK);
        check.setResult(TestResult.TRUE);

        GuidelineCheckCondition condition =
            new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.TRUE);
        check.setCondition(condition);

        GuidelineCheckResult result = new GuidelineCheckResult("test");

        if (check.passesCondition(report)) {
            check.evaluate(report, result);
        }

        Assert.assertNull(result.getStatus());
    }
}
