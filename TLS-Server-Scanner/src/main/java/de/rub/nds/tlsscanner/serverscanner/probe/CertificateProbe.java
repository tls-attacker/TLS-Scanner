/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.util.CertificateFetcher;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.CertificateResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.crypto.tls.Certificate;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateProbe extends TlsProbe {

    public CertificateProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.CERTIFICATE, config);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            Config tlsConfig = getScannerConfig().createConfig();
            tlsConfig.setQuickReceive(true);
            tlsConfig.setEarlyStop(true);
            tlsConfig.setStopActionsAfterIOException(true);
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.HELLO);
            tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
            tlsConfig.setAddServerNameIndicationExtension(true);
            tlsConfig.setAddECPointFormatExtension(true);
            tlsConfig.setAddEllipticCurveExtension(true);
            List<CipherSuite> toTestList = new LinkedList<>();
            toTestList.addAll(Arrays.asList(CipherSuite.values()));
            List<NamedGroup> namedGroups = Arrays.asList(NamedGroup.values());
            tlsConfig.setDefaultClientNamedGroups(namedGroups);
            List<SignatureAndHashAlgorithm> sigHashAlgos = Arrays.asList(SignatureAndHashAlgorithm.values());
            tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(sigHashAlgos);
            toTestList.remove(CipherSuite.TLS_FALLBACK_SCSV);
            toTestList.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
            tlsConfig.setDefaultClientSupportedCiphersuites(toTestList);
            tlsConfig.setStopActionsAfterFatal(true);
            Certificate serverCert = CertificateFetcher.fetchServerCertificate(tlsConfig);
            if (serverCert != null) {
                CertificateChain chain = new CertificateChain(serverCert, tlsConfig.getDefaultClientConnection()
                        .getHostname());
                return new CertificateResult(chain);
            } else {
                return getCouldNotExecuteResult();
            }
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new CertificateResult(null);
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new CertificateResult(null);
    }
}
