/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.ExtensionGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import org.junit.jupiter.api.Test;

import java.util.Collections;

public class ExtensionGuidelineCheckTest {

    @Test
    public void testPositive() {
        ServerReport report = new ServerReport("test", 443);
        report.setSupportedExtensions(Collections.singletonList(ExtensionType.COOKIE));

        ExtensionGuidelineCheck check = new ExtensionGuidelineCheck(null, null, ExtensionType.COOKIE);
        GuidelineCheckResult result = check.evaluate(report);
        assertEquals(TestResults.TRUE, result.getResult());
    }

    @Test
    public void testNegative() {
        ServerReport report = new ServerReport("test", 443);
        report.setSupportedExtensions(Collections.emptyList());

        ExtensionGuidelineCheck check = new ExtensionGuidelineCheck(null, null, ExtensionType.COOKIE);
        GuidelineCheckResult result = check.evaluate(report);
        assertEquals(TestResults.FALSE, result.getResult());
    }
}
