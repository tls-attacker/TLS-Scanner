/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.NamedGroupsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

public class NamedGroupsGuidelineCheckTest {

    @Test
    public void testPositive() {
        SiteReport report = new SiteReport("test", 443);
        report.setSupportedNamedGroups(Arrays.asList(NamedGroup.SECP160K1, NamedGroup.SECP160R1));

        NamedGroupsGuidelineCheck check =
            new NamedGroupsGuidelineCheck(null, null, Arrays.asList(NamedGroup.SECP160K1, NamedGroup.SECP160R1),
                Collections.singletonList(NamedGroup.SECP160K1), false, 1);
        GuidelineCheckResult result = check.evaluate(report);
        Assert.assertEquals(TestResult.TRUE, result.getResult());
    }

    @Test
    public void testNegative() {
        SiteReport report = new SiteReport("test", 443);
        report.setSupportedNamedGroups(Arrays.asList(NamedGroup.SECP160K1, NamedGroup.SECP160R1));

        NamedGroupsGuidelineCheck check =
            new NamedGroupsGuidelineCheck(null, null, Arrays.asList(NamedGroup.SECP160K1, NamedGroup.SECP160R1),
                Collections.singletonList(NamedGroup.SECP256R1), false, 1);
        GuidelineCheckResult result = check.evaluate(report);
        Assert.assertEquals(TestResult.FALSE, result.getResult());

        check = new NamedGroupsGuidelineCheck(null, null, Collections.singletonList(NamedGroup.SECP160R1),
            Collections.singletonList(NamedGroup.SECP160K1), false, 1);
        result = check.evaluate(report);
        Assert.assertEquals(TestResult.FALSE, result.getResult());
    }
}
