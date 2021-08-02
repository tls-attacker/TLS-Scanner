/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CipherSuiteGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.ExtensionGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

public class ExtensionGuidelineCheckTest {

    @Test
    public void testPositive() {
        SiteReport report = new SiteReport("test");
        report.setSupportedExtensions(Collections.singletonList(ExtensionType.COOKIE));

        ExtensionGuidelineCheck check = new ExtensionGuidelineCheck();
        check.setExtension(ExtensionType.COOKIE);
        GuidelineCheckResult result = new GuidelineCheckResult("test");
        check.evaluate(report, result);
        Assert.assertEquals(GuidelineCheckStatus.PASSED, result.getStatus());
    }

    @Test
    public void testNegative() {
        SiteReport report = new SiteReport("test");
        report.setSupportedExtensions(Collections.emptyList());

        ExtensionGuidelineCheck check = new ExtensionGuidelineCheck();
        check.setExtension(ExtensionType.COOKIE);
        GuidelineCheckResult result = new GuidelineCheckResult("test");
        check.evaluate(report, result);
        Assert.assertEquals(GuidelineCheckStatus.FAILED, result.getStatus());
    }
}
