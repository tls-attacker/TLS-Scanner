/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.probe.result;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.scanner.core.constants.TestResult;
import java.util.List;

public class VersionResult extends ProbeResult<ClientReport> {

    private final List<ProtocolVersion> supportedProtocolVersions;
    private final List<ProtocolVersion> unsupportedProtocolVersions;

    public VersionResult(List<ProtocolVersion> supportedVersions, List<ProtocolVersion> unsupportedVersions) {
        super(TlsProbeType.PROTOCOL_VERSION);
        this.supportedProtocolVersions = supportedVersions;
        this.unsupportedProtocolVersions = unsupportedVersions;
    }

    @Override
    protected void mergeData(ClientReport report) {
        if (supportedProtocolVersions != null) {
            report.setSupportedVersions(supportedProtocolVersions);

            for (ProtocolVersion version : supportedProtocolVersions) {
                if (version == ProtocolVersion.SSL2) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_SSL_2, TestResult.TRUE);
                }
                if (version == ProtocolVersion.SSL3) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_SSL_3, TestResult.TRUE);
                }
                if (version == ProtocolVersion.TLS10) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_0, TestResult.TRUE);
                }
                if (version == ProtocolVersion.TLS11) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_1, TestResult.TRUE);
                }
                if (version == ProtocolVersion.TLS12) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.TRUE);
                }
                if (version == ProtocolVersion.TLS13) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.TRUE);
                }
            }

            for (ProtocolVersion version : unsupportedProtocolVersions) {
                if (version == ProtocolVersion.SSL2) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_SSL_2, TestResult.FALSE);
                }
                if (version == ProtocolVersion.SSL3) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_SSL_3, TestResult.FALSE);
                }
                if (version == ProtocolVersion.TLS10) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_0, TestResult.FALSE);
                }
                if (version == ProtocolVersion.TLS11) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_1, TestResult.FALSE);
                }
                if (version == ProtocolVersion.TLS12) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.FALSE);
                }
                if (version == ProtocolVersion.TLS13) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.FALSE);
                }
            }
        } else {
            report.putResult(TlsAnalyzedProperty.SUPPORTS_SSL_2, TestResult.COULD_NOT_TEST);
            report.putResult(TlsAnalyzedProperty.SUPPORTS_SSL_3, TestResult.COULD_NOT_TEST);
            report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_0, TestResult.COULD_NOT_TEST);
            report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_1, TestResult.COULD_NOT_TEST);
            report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.COULD_NOT_TEST);
            report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.COULD_NOT_TEST);
        }
    }

}
