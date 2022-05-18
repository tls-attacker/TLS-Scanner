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
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.constants.ApplicationProtocol;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.List;

public class DtlsApplicationFingerprintResult extends ProbeResult<ServerReport> {

    private List<ApplicationProtocol> supportedApplications;
    private TestResult isAcceptingUnencryptedAppData;

    public DtlsApplicationFingerprintResult(List<ApplicationProtocol> supportedApplications,
        TestResult isAcceptingUnencryptedAppData) {
        super(TlsProbeType.DTLS_APPLICATION_FINGERPRINT);
        this.supportedApplications = supportedApplications;
        this.isAcceptingUnencryptedAppData = isAcceptingUnencryptedAppData;
    }

    @Override
    protected void mergeData(ServerReport report) {
        report.setSupportedApplications(supportedApplications);
        report.putResult(TlsAnalyzedProperty.ACCEPTS_UNENCRYPTED_APP_DATA, isAcceptingUnencryptedAppData);
    }

}