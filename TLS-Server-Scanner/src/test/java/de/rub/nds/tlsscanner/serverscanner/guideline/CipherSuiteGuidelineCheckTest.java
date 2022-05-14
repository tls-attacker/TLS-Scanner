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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CipherSuiteGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.Arrays;
import java.util.Collections;
import org.junit.Assert;
import org.junit.Test;

public class CipherSuiteGuidelineCheckTest {

    @Test
    public void testPositive() {
        ServerReport report = new ServerReport("test", 443);
        report.putResult(TlsAnalyzedProperty.LIST_VERSIONSUITE_PAIRS,
            new ListResult<>(Arrays.asList(
                new VersionSuiteListPair(ProtocolVersion.TLS12,
                    Collections.singletonList(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256)),
                new VersionSuiteListPair(ProtocolVersion.TLS13,
                    Collections.singletonList(CipherSuite.TLS_AES_128_GCM_SHA256))),
                "VERSIONSUITE_PAIRS"));

        CipherSuiteGuidelineCheck check =
            new CipherSuiteGuidelineCheck(null, null, Collections.singletonList(ProtocolVersion.TLS12),
                Collections.singletonList(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256));
        GuidelineCheckResult result = check.evaluate(report);
        Assert.assertEquals(TestResults.TRUE, result.getResult());

        check = new CipherSuiteGuidelineCheck(null, null, Collections.singletonList(ProtocolVersion.TLS13),
            Collections.singletonList(CipherSuite.TLS_AES_128_GCM_SHA256));

        result = check.evaluate(report);
        Assert.assertEquals(TestResults.TRUE, result.getResult());
    }

    @Test
    public void testNegative() {
        ServerReport report = new ServerReport("test", 443);
        report.putResult(TlsAnalyzedProperty.LIST_VERSIONSUITE_PAIRS,
            new ListResult<>(
                Collections.singletonList(new VersionSuiteListPair(ProtocolVersion.TLS12, Arrays
                    .asList(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384))),
                "VERSIONSUITE_PAIRS"));

        CipherSuiteGuidelineCheck check =
            new CipherSuiteGuidelineCheck(null, null, Collections.singletonList(ProtocolVersion.TLS12),
                Collections.singletonList(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256));
        GuidelineCheckResult result = check.evaluate(report);
        Assert.assertEquals(TestResults.FALSE, result.getResult());
    }
}
