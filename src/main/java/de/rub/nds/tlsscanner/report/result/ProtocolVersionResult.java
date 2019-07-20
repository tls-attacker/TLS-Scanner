/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.List;

public class ProtocolVersionResult extends ProbeResult {

    private final List<ProtocolVersion> supportedProtocolVersions;

    private final List<ProtocolVersion> unsupportedProtocolVersions;

    public ProtocolVersionResult(List<ProtocolVersion> supportedProtocolVersions, List<ProtocolVersion> unsupportedProtocolVersions) {
        super(ProbeType.PROTOCOL_VERSION);
        this.supportedProtocolVersions = supportedProtocolVersions;
        this.unsupportedProtocolVersions = unsupportedProtocolVersions;
    }

    @Override
    public void mergeData(SiteReport report) {
        if (supportedProtocolVersions.size() > 0) {
            report.setSupportsSslTls(true);
        }
        report.setVersions(supportedProtocolVersions);
        for (ProtocolVersion version : supportedProtocolVersions) {
            if (version == ProtocolVersion.DTLS10) {
                report.putResult(AnalyzedProperty.SUPPORTS_DTLS_1_0, TestResult.TRUE);
            }
            if (version == ProtocolVersion.DTLS12) {
                report.putResult(AnalyzedProperty.SUPPORTS_DTLS_1_2, TestResult.TRUE);
            }
            if (version == ProtocolVersion.SSL2) {
                report.putResult(AnalyzedProperty.SUPPORTS_SSL_2, TestResult.TRUE);
            }
            if (version == ProtocolVersion.SSL3) {
                report.putResult(AnalyzedProperty.SUPPORTS_SSL_3, TestResult.TRUE);
            }
            if (version == ProtocolVersion.TLS10) {
                report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_0, TestResult.TRUE);
            }
            if (version == ProtocolVersion.TLS11) {
                report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_1, TestResult.TRUE);
            }
            if (version == ProtocolVersion.TLS12) {
                report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.TRUE);
            }
        }

        for (ProtocolVersion version : unsupportedProtocolVersions) {
            if (version == ProtocolVersion.DTLS10) {
                report.putResult(AnalyzedProperty.SUPPORTS_DTLS_1_0, TestResult.FALSE);
            }
            if (version == ProtocolVersion.DTLS12) {
                report.putResult(AnalyzedProperty.SUPPORTS_DTLS_1_2, TestResult.FALSE);
            }
            if (version == ProtocolVersion.SSL2) {
                report.putResult(AnalyzedProperty.SUPPORTS_SSL_2, TestResult.FALSE);
            }
            if (version == ProtocolVersion.SSL3) {
                report.putResult(AnalyzedProperty.SUPPORTS_SSL_3, TestResult.FALSE);
            }
            if (version == ProtocolVersion.TLS10) {
                report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_0, TestResult.FALSE);
            }
            if (version == ProtocolVersion.TLS11) {
                report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_1, TestResult.FALSE);
            }
            if (version == ProtocolVersion.TLS12) {
                report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.FALSE);
            }
            if (version == ProtocolVersion.TLS13) {
                report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.FALSE);
            }
            if (version == ProtocolVersion.TLS13_DRAFT14) {
                report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_14, TestResult.FALSE);
            }
            if (version == ProtocolVersion.TLS13_DRAFT15) {
                report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_15, TestResult.FALSE);
            }
            if (version == ProtocolVersion.TLS13_DRAFT16) {
                report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_16, TestResult.FALSE);
            }
            if (version == ProtocolVersion.TLS13_DRAFT17) {
                report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_17, TestResult.FALSE);
            }
            if (version == ProtocolVersion.TLS13_DRAFT18) {
                report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_18, TestResult.FALSE);
            }
            if (version == ProtocolVersion.TLS13_DRAFT19) {
                report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_19, TestResult.FALSE);
            }
            if (version == ProtocolVersion.TLS13_DRAFT20) {
                report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_20, TestResult.FALSE);
            }
            if (version == ProtocolVersion.TLS13_DRAFT21) {
                report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_21, TestResult.FALSE);
            }
            if (version == ProtocolVersion.TLS13_DRAFT22) {
                report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_22, TestResult.FALSE);
            }
        }
        report.setVersions(supportedProtocolVersions);
    }

}
