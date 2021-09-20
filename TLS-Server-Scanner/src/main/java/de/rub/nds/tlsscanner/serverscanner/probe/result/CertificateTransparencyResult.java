/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsattacker.core.certificate.transparency.SignedCertificateTimestampList;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class CertificateTransparencyResult extends ProbeResult<ServerReport> {

    private TestResult supportsPrecertificateSCTs;
    private TestResult supportsHandshakeSCTs;
    private TestResult supportsOcspSCTs;
    private TestResult meetsChromeCTPolicy;
    private SignedCertificateTimestampList precertificateSctList;
    private SignedCertificateTimestampList handshakeSctList;
    private SignedCertificateTimestampList ocspSctList;

    public CertificateTransparencyResult(TestResult supportsPrecertificateSCTs, TestResult supportsHandshakeSCTs,
        TestResult supportsOcspSCTs, TestResult meetsChromeCTPolicy,
        SignedCertificateTimestampList precertificateSctList, SignedCertificateTimestampList handshakeSctList,
        SignedCertificateTimestampList ocspSctList) {
        super(ProbeType.CERTIFICATE_TRANSPARENCY);
        this.supportsPrecertificateSCTs = supportsPrecertificateSCTs;
        this.supportsHandshakeSCTs = supportsHandshakeSCTs;
        this.supportsOcspSCTs = supportsOcspSCTs;
        this.meetsChromeCTPolicy = meetsChromeCTPolicy;
        this.precertificateSctList = precertificateSctList;
        this.handshakeSctList = handshakeSctList;
        this.ocspSctList = ocspSctList;

    }

    @Override
    protected void mergeData(ServerReport report) {
        report.setPrecertificateSctList(precertificateSctList);
        report.setHandshakeSctList(handshakeSctList);
        report.setOcspSctList(ocspSctList);

        report.putResult(TlsAnalyzedProperty.SUPPORTS_SCTS_PRECERTIFICATE, supportsPrecertificateSCTs);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_SCTS_HANDSHAKE, supportsHandshakeSCTs);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_SCTS_OCSP, supportsOcspSCTs);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_CHROME_CT_POLICY, meetsChromeCTPolicy);
    }
}
