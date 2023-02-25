/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.result;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;

public class DtlsFragmentationResult<Report extends TlsScanReport> extends ProbeResult<Report> {

    private TestResult supportsDirectly;
    private TestResult supportsDirectlyIndPackets;
    private TestResult supportsAfterCookieExchange;
    private TestResult supportsAfterCookieExchangeIndPackets;
    private TestResult supportsWithExtension;
    private TestResult supportsWithExtensionIndPackets;

    public DtlsFragmentationResult(
            TestResult supportsDirectly,
            TestResult supportsDirectlyIndPackets,
            TestResult supportsAfterCookieExchange,
            TestResult supportsAfterCookieExchangeIndPackets,
            TestResult supportsWithExtension,
            TestResult supportsWithExtensionIndPackets) {
        super(TlsProbeType.DTLS_FRAGMENTATION);
        this.supportsDirectly = supportsDirectly;
        this.supportsDirectlyIndPackets = supportsDirectlyIndPackets;
        this.supportsAfterCookieExchange = supportsAfterCookieExchange;
        this.supportsAfterCookieExchangeIndPackets = supportsAfterCookieExchangeIndPackets;
        this.supportsWithExtension = supportsWithExtension;
        this.supportsWithExtensionIndPackets = supportsWithExtensionIndPackets;
    }

    @Override
    protected void mergeData(Report report) {
        if (supportsDirectly == TestResults.TRUE) {
            report.putResult(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION, TestResults.TRUE);
            report.putResult(
                    TlsAnalyzedProperty.DTLS_FRAGMENTATION_REQUIRES_EXTENSION, TestResults.FALSE);
        } else if (supportsAfterCookieExchange == TestResults.TRUE) {
            report.putResult(
                    TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION, TestResults.PARTIALLY);
            report.putResult(
                    TlsAnalyzedProperty.DTLS_FRAGMENTATION_REQUIRES_EXTENSION, TestResults.FALSE);
        } else if (supportsWithExtension == TestResults.TRUE) {
            report.putResult(
                    TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION, TestResults.PARTIALLY);
            report.putResult(
                    TlsAnalyzedProperty.DTLS_FRAGMENTATION_REQUIRES_EXTENSION, TestResults.TRUE);
        } else {
            report.putResult(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION, TestResults.FALSE);
            report.putResult(
                    TlsAnalyzedProperty.DTLS_FRAGMENTATION_REQUIRES_EXTENSION, TestResults.FALSE);
        }

        if (supportsDirectlyIndPackets == TestResults.TRUE) {
            report.putResult(
                    TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS,
                    TestResults.TRUE);
            report.putResult(
                    TlsAnalyzedProperty
                            .DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS_REQUIRES_EXTENSION,
                    TestResults.FALSE);
        } else if (supportsAfterCookieExchangeIndPackets == TestResults.TRUE) {
            report.putResult(
                    TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS,
                    TestResults.PARTIALLY);
            report.putResult(
                    TlsAnalyzedProperty
                            .DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS_REQUIRES_EXTENSION,
                    TestResults.FALSE);
        } else if (supportsWithExtensionIndPackets == TestResults.TRUE) {
            report.putResult(
                    TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS,
                    TestResults.PARTIALLY);
            report.putResult(
                    TlsAnalyzedProperty
                            .DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS_REQUIRES_EXTENSION,
                    TestResults.TRUE);
        } else {
            report.putResult(
                    TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS,
                    TestResults.FALSE);
            report.putResult(
                    TlsAnalyzedProperty
                            .DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS_REQUIRES_EXTENSION,
                    TestResults.FALSE);
        }
    }
}
