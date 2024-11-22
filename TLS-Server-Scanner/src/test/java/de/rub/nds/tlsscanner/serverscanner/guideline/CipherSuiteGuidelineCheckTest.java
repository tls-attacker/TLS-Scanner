/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CipherSuiteGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.Arrays;
import java.util.Collections;
import org.junit.jupiter.api.Test;

public class CipherSuiteGuidelineCheckTest {

    @Test
    public void testPositive() {
        ServerReport report = new ServerReport("test", 443);
        report.putResult(
                TlsAnalyzedProperty.VERSION_SUITE_PAIRS,
                Arrays.asList(
                        new VersionSuiteListPair(
                                ProtocolVersion.TLS12,
                                Collections.singletonList(
                                        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256)),
                        new VersionSuiteListPair(
                                ProtocolVersion.TLS13,
                                Collections.singletonList(CipherSuite.TLS_AES_128_GCM_SHA256))));
        CipherSuiteGuidelineCheck check =
                new CipherSuiteGuidelineCheck(
                        null,
                        null,
                        Collections.singletonList(ProtocolVersion.TLS12),
                        Collections.singletonList(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256));
        GuidelineCheckResult result = check.evaluate(report);
        assertEquals(GuidelineAdherence.ADHERED, result.getAdherence());

        check =
                new CipherSuiteGuidelineCheck(
                        null,
                        null,
                        Collections.singletonList(ProtocolVersion.TLS13),
                        Collections.singletonList(CipherSuite.TLS_AES_128_GCM_SHA256));

        result = check.evaluate(report);
        assertEquals(GuidelineAdherence.ADHERED, result.getAdherence());
    }

    @Test
    public void testNegative() {
        ServerReport report = new ServerReport("test", 443);
        report.putResult(
                TlsAnalyzedProperty.VERSION_SUITE_PAIRS,
                Collections.singletonList(
                        new VersionSuiteListPair(
                                ProtocolVersion.TLS12,
                                Arrays.asList(
                                        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                                        CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384))));

        CipherSuiteGuidelineCheck check =
                new CipherSuiteGuidelineCheck(
                        null,
                        null,
                        Collections.singletonList(ProtocolVersion.TLS12),
                        Collections.singletonList(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256));
        GuidelineCheckResult result = check.evaluate(report);
        assertEquals(GuidelineAdherence.VIOLATED, result.getAdherence());
    }
}
