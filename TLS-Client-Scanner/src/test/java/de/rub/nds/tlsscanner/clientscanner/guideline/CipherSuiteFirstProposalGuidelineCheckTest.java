/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.guideline;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.clientscanner.guideline.checks.CipherSuiteFirstProposalGuidelineCheck;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import java.util.Arrays;
import java.util.Collections;
import org.junit.jupiter.api.Test;

public class CipherSuiteFirstProposalGuidelineCheckTest {

    @Test
    public void testPositive() {
        ClientReport report = new ClientReport();
        report.putResult(
                TlsAnalyzedProperty.VERSION_SUITE_PAIRS,
                Arrays.asList(
                        new VersionSuiteListPair(
                                ProtocolVersion.TLS12,
                                Arrays.asList(
                                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)),
                        new VersionSuiteListPair(
                                ProtocolVersion.TLS13,
                                Collections.singletonList(CipherSuite.TLS_AES_128_GCM_SHA256))));
        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS,
                Arrays.asList(ProtocolVersion.TLS12, ProtocolVersion.TLS13));

        CipherSuiteFirstProposalGuidelineCheck check =
                new CipherSuiteFirstProposalGuidelineCheck(null, null);
        GuidelineCheckResult result = check.evaluate(report);
        assertEquals(GuidelineAdherence.ADHERED, result.getAdherence());
    }

    @Test
    public void testConditionNotMet() {
        ClientReport report = new ClientReport();
        report.putResult(
                TlsAnalyzedProperty.VERSION_SUITE_PAIRS,
                Arrays.asList(
                        new VersionSuiteListPair(
                                ProtocolVersion.TLS13,
                                Collections.singletonList(CipherSuite.TLS_AES_128_GCM_SHA256))));
        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS,
                Arrays.asList(ProtocolVersion.TLS13));

        CipherSuiteFirstProposalGuidelineCheck check =
                new CipherSuiteFirstProposalGuidelineCheck(null, null);
        GuidelineCheckResult result = check.evaluate(report);
        assertEquals(GuidelineAdherence.CONDITION_NOT_MET, result.getAdherence());
    }

    @Test
    public void testNegative() {
        ClientReport report = new ClientReport();
        report.putResult(
                TlsAnalyzedProperty.VERSION_SUITE_PAIRS,
                Arrays.asList(
                        new VersionSuiteListPair(
                                ProtocolVersion.TLS12,
                                Arrays.asList(
                                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)),
                        new VersionSuiteListPair(
                                ProtocolVersion.TLS13,
                                Collections.singletonList(
                                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256))));
        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS,
                Arrays.asList(ProtocolVersion.TLS12, ProtocolVersion.TLS13));

        CipherSuiteFirstProposalGuidelineCheck check =
                new CipherSuiteFirstProposalGuidelineCheck(null, null);
        GuidelineCheckResult result = check.evaluate(report);
        assertEquals(GuidelineAdherence.VIOLATED, result.getAdherence());
    }
}
