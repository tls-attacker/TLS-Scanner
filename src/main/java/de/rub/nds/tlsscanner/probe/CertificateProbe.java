/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.result.CertificateResult;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.util.CertificateFetcher;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.ResultValue;
import de.rub.nds.tlsscanner.probe.certificate.CertificateJudger;
import de.rub.nds.tlsscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.probe.certificate.CertificateReportGenerator;
import de.rub.nds.tlsscanner.report.check.TlsCheck;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.crypto.tls.Certificate;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateProbe extends TlsProbe {

    public CertificateProbe(ScannerConfig config) {
        super(ProbeType.CERTIFICATE, config, 0);
    }

    @Override
    public ProbeResult call() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.HELLO);
        tlsConfig.setSniHostname(tlsConfig.getDefaultClientConnection().getHostname());
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setStopActionsAfterFatal(true);
        Certificate serverCert = CertificateFetcher.fetchServerCertificate(tlsConfig);
        List<CertificateReport> reportList = CertificateReportGenerator.generateReports(serverCert);
        return new CertificateResult(getType(), reportList);
    }
}
