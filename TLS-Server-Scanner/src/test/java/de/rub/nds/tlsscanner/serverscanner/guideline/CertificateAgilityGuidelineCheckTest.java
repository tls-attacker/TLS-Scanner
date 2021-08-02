/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateAgilityGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import org.junit.Assert;
import org.junit.Test;

public class CertificateAgilityGuidelineCheckTest {

    @Test
    public void testNegative() {
        SiteReport report = new SiteReport("test");

        CertificateAgilityGuidelineCheck check = new CertificateAgilityGuidelineCheck();

        GuidelineCheckResult result = new GuidelineCheckResult("test");

        check.evaluate(report, result);

        Assert.assertEquals(GuidelineCheckStatus.FAILED, result.getStatus());
    }
}
