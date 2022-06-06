/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.NamedGroupsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.Arrays;
import java.util.Collections;
import org.junit.Assert;
import org.junit.Test;

public class NamedGroupsGuidelineCheckTest {

    @Test
    public void testPositive() {
        ServerReport report = new ServerReport("test", 443);
        report.putResult(TlsAnalyzedProperty.SUPPORTED_NAMEDGROUPS,
            new ListResult<>(Arrays.asList(NamedGroup.SECP160K1, NamedGroup.SECP160R1), "SUPPORTED_NAMEDGROUPS"));

        NamedGroupsGuidelineCheck check =
            new NamedGroupsGuidelineCheck(null, null, Arrays.asList(NamedGroup.SECP160K1, NamedGroup.SECP160R1),
                Collections.singletonList(NamedGroup.SECP160K1), false, 1);
        GuidelineCheckResult result = check.evaluate(report);
        Assert.assertEquals(TestResults.TRUE, result.getResult());
    }

    @Test
    public void testNegative() {
        ServerReport report = new ServerReport("test", 443);
        report.putResult(TlsAnalyzedProperty.SUPPORTED_NAMEDGROUPS,
            new ListResult<>(Arrays.asList(NamedGroup.SECP160K1, NamedGroup.SECP160R1), "SUPPORTED_NAMEDGROUPS"));

        NamedGroupsGuidelineCheck check =
            new NamedGroupsGuidelineCheck(null, null, Arrays.asList(NamedGroup.SECP160K1, NamedGroup.SECP160R1),
                Collections.singletonList(NamedGroup.SECP256R1), false, 1);
        GuidelineCheckResult result = check.evaluate(report);
        Assert.assertEquals(TestResults.FALSE, result.getResult());

        check = new NamedGroupsGuidelineCheck(null, null, Collections.singletonList(NamedGroup.SECP160R1),
            Collections.singletonList(NamedGroup.SECP160K1), false, 1);
        result = check.evaluate(report);
        Assert.assertEquals(TestResults.FALSE, result.getResult());
    }
}
