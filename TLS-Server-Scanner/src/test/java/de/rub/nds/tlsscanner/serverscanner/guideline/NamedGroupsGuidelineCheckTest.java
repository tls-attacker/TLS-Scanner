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
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.HashAlgorithmsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.NamedGroupsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

public class NamedGroupsGuidelineCheckTest {

    @Test
    public void testPositive() {
        SiteReport report = new SiteReport("test");
        report.setSupportedNamedGroups(Arrays.asList(NamedGroup.SECP160K1, NamedGroup.SECP160R1));

        NamedGroupsGuidelineCheck check = new NamedGroupsGuidelineCheck();
        check.setGroups(Arrays.asList(NamedGroup.SECP160K1, NamedGroup.SECP160R1));
        check.setRequired(Collections.singletonList(NamedGroup.SECP160K1));
        GuidelineCheckResult result = new GuidelineCheckResult("test");
        check.evaluate(report, result);
        Assert.assertEquals(GuidelineCheckStatus.PASSED, result.getStatus());
    }

    @Test
    public void testNegative() {
        SiteReport report = new SiteReport("test");
        report.setSupportedNamedGroups(Arrays.asList(NamedGroup.SECP160K1, NamedGroup.SECP160R1));

        NamedGroupsGuidelineCheck check = new NamedGroupsGuidelineCheck();
        check.setGroups(Arrays.asList(NamedGroup.SECP160K1, NamedGroup.SECP160R1));
        check.setRequired(Collections.singletonList(NamedGroup.SECP256R1));
        GuidelineCheckResult result = new GuidelineCheckResult("test");
        check.evaluate(report, result);
        Assert.assertEquals(GuidelineCheckStatus.FAILED, result.getStatus());

        check = new NamedGroupsGuidelineCheck();
        check.setGroups(Collections.singletonList(NamedGroup.SECP160R1));
        check.setRequired(Collections.singletonList(NamedGroup.SECP160K1));
        result = new GuidelineCheckResult("test");
        check.evaluate(report, result);
        Assert.assertEquals(GuidelineCheckStatus.FAILED, result.getStatus());
    }
}
