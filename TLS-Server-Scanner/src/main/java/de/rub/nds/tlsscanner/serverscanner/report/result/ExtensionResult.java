/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResults;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.List;

public class ExtensionResult extends ProbeResult {

    private List<ExtensionType> allSupportedExtensions;
    private TestResult extendedMasterSecret = TestResults.FALSE;
    private TestResult encryptThenMac = TestResults.FALSE;
    private TestResult secureRenegotiation = TestResults.FALSE;
    private TestResult sessionTickets = TestResults.FALSE;
    private TestResult certStatusRequest = TestResults.FALSE;
    private TestResult certStatusRequestV2 = TestResults.FALSE;

    public ExtensionResult(List<ExtensionType> allSupportedExtensions) {
        super(ProbeType.EXTENSIONS);
        this.allSupportedExtensions = allSupportedExtensions;
    }

    @Override
    public void mergeData(SiteReport report) {
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
        report.putResult(AnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET, extendedMasterSecret);
        report.putResult(AnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC, encryptThenMac);
        report.putResult(AnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION, secureRenegotiation);
        report.putResult(AnalyzedProperty.SUPPORTS_SESSION_TICKETS, sessionTickets);
        report.putResult(AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST, certStatusRequest);
        report.putResult(AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_V2, certStatusRequestV2);
    }

}
