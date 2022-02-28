/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.HashAlgorithmsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResults;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.Collections;
import org.junit.Assert;
import org.junit.Test;

public class HashAlgorithmsGuidelineCheckTest {

    @Test
    public void testPositive() {
        SiteReport report = new SiteReport("test", 443);
        report.setSupportedSignatureAndHashAlgorithmsSke(Collections.singletonList(SignatureAndHashAlgorithm.RSA_SHA1));

        HashAlgorithmsGuidelineCheck check = new HashAlgorithmsGuidelineCheck(null, null,
            Collections.singletonList(SignatureAndHashAlgorithm.RSA_SHA1.getHashAlgorithm()));
        GuidelineCheckResult result = check.evaluate(report);
        Assert.assertEquals(TestResults.TRUE, result.getResult());
    }

    @Test
    public void testNegative() {
        SiteReport report = new SiteReport("test", 443);
        report
            .setSupportedSignatureAndHashAlgorithmsSke(Collections.singletonList(SignatureAndHashAlgorithm.RSA_SHA224));

        HashAlgorithmsGuidelineCheck check = new HashAlgorithmsGuidelineCheck(null, null,
            Collections.singletonList(SignatureAndHashAlgorithm.RSA_SHA1.getHashAlgorithm()));
        GuidelineCheckResult result = check.evaluate(report);
        Assert.assertEquals(TestResults.FALSE, result.getResult());
    }
}
