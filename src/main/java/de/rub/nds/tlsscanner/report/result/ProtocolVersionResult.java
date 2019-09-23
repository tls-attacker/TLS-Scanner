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
        if (supportedProtocolVersions != null && supportedProtocolVersions.size() > 0) {
            report.setSupportsSslTls(true);
        }
        if (supportedProtocolVersions != null) {
            report.setVersions(supportedProtocolVersions);

            for (ProtocolVersion version : supportedProtocolVersions) {
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
            }
        } else {
            report.putResult(AnalyzedProperty.SUPPORTS_SSL_2, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.SUPPORTS_SSL_3, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_0, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_1, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.COULD_NOT_TEST);
        }
        report.setVersions(supportedProtocolVersions);
    }

}
