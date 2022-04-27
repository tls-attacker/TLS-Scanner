/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.List;

public class ExtensionResult extends ProbeResult<ServerReport> {

    private final List<ExtensionType> allSupportedExtensions;
    private TestResult extendedMasterSecret = TestResults.FALSE;
    private TestResult encryptThenMac = TestResults.FALSE;
    private TestResult secureRenegotiation = TestResults.FALSE;
    private TestResult sessionTickets = TestResults.FALSE;
    private TestResult certStatusRequest = TestResults.FALSE;
    private TestResult certStatusRequestV2 = TestResults.FALSE;

    public ExtensionResult(List<ExtensionType> allSupportedExtensions) {
        super(TlsProbeType.EXTENSIONS);
        this.allSupportedExtensions = allSupportedExtensions;
    }

    @Override
    public void mergeData(ServerReport report) {
        if (report.getSupportedExtensions() == null) {
            report.setSupportedExtensions(allSupportedExtensions);
        } else {
            report.getSupportedExtensions().addAll(allSupportedExtensions);
        }
        if (allSupportedExtensions != null) {
            for (ExtensionType type : allSupportedExtensions) {
                if (type == ExtensionType.ENCRYPT_THEN_MAC) {
                    encryptThenMac = TestResults.TRUE;
                }
                if (type == ExtensionType.EXTENDED_MASTER_SECRET) {
                    extendedMasterSecret = TestResults.TRUE;
                }
                if (type == ExtensionType.RENEGOTIATION_INFO) {
                    secureRenegotiation = TestResults.TRUE;
                }
                if (type == ExtensionType.SESSION_TICKET) {
                    sessionTickets = TestResults.TRUE;
                }
                if (type == ExtensionType.STATUS_REQUEST) {
                    certStatusRequest = TestResults.TRUE;
                }
                if (type == ExtensionType.STATUS_REQUEST_V2) {
                    certStatusRequestV2 = TestResults.TRUE;
                }
            }
        } else {
            encryptThenMac = TestResults.COULD_NOT_TEST;
            extendedMasterSecret = TestResults.COULD_NOT_TEST;
            secureRenegotiation = TestResults.COULD_NOT_TEST;
            sessionTickets = TestResults.COULD_NOT_TEST;
            certStatusRequest = TestResults.COULD_NOT_TEST;
            certStatusRequestV2 = TestResults.COULD_NOT_TEST;
        }
        report.putResult(TlsAnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET, extendedMasterSecret);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC, encryptThenMac);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION, secureRenegotiation);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_SESSION_TICKETS, sessionTickets);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST, certStatusRequest);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_V2, certStatusRequestV2);
    }

}
