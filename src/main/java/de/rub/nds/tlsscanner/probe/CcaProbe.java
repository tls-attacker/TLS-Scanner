/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.attacks.cca.CcaCertificateGenerator;
import de.rub.nds.tlsattacker.attacks.cca.CcaCertificateType;
import de.rub.nds.tlsattacker.attacks.cca.CcaWorkflowGenerator;
import de.rub.nds.tlsattacker.attacks.cca.CcaWorkflowType;
import de.rub.nds.tlsattacker.attacks.config.CcaCommandConfig;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.CcaDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.CcaResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.cca.CcaTestResult;

import java.util.LinkedList;
import java.util.List;

public class CcaProbe extends TlsProbe {
    private List<CipherSuite> suiteList;

    public CcaProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.CCA, config, 5);
        suiteList = new LinkedList<>();
    }

    @Override
    public ProbeResult executeTest() {
        CcaCommandConfig ccaConfig = new CcaCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) ccaConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
        CcaDelegate ccaDelegate = (CcaDelegate) getScannerConfig().getDelegate(CcaDelegate.class);

        List<CipherSuite> cipherSuites = new LinkedList<>();
        List<ProtocolVersion> protocolVersions = new LinkedList<>();

        if (getScannerConfig().getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
            /*
            Note that this is far from optimal. We will get connection errors due to no ciphersuites in common.
            Ideally we'd just want to iterate all cipher suites the SUT supports.
             */
            cipherSuites.addAll(CipherSuite.getImplemented());
            cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
            cipherSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

            protocolVersions.add(ProtocolVersion.TLS10);
            protocolVersions.add(ProtocolVersion.TLS11);
            protocolVersions.add(ProtocolVersion.TLS12);

        } else {
            /* We only want to test a single cipher suite. It appears that the framework currently does not provide a way
            to access the cipher suites the scanned target supports. Ideally we would pick one from those.
            For now I'll go with a decent default.
            */
            cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256);
            protocolVersions.add(ProtocolVersion.TLS12);
        }



        List<CcaTestResult> resultList = new LinkedList<>();
        Boolean bypassable = false;
        for (CcaWorkflowType ccaWorkflowType : CcaWorkflowType.values()) {
            for (CcaCertificateType ccaCertificateType : CcaCertificateType.values()) {
                for (ProtocolVersion protocolVersion : protocolVersions) {
                    for (CipherSuite cipherSuite : cipherSuites) {
                        CertificateMessage certificateMessage = null;
                        Config tlsConfig = ccaConfig.createConfig();
                        tlsConfig.setDefaultClientSupportedCiphersuites(cipherSuite);
                        tlsConfig.setHighestProtocolVersion(protocolVersion);
                        certificateMessage = CcaCertificateGenerator.generateCertificate(ccaDelegate, ccaConfig, ccaCertificateType);
                        WorkflowTrace trace = CcaWorkflowGenerator.generateWorkflow(tlsConfig, ccaWorkflowType,
                                certificateMessage);
                        State state = new State(tlsConfig, trace);
                        try {
                            executeState(state);
                        } catch (Exception E) {
                            LOGGER.error("Error while testing for client authentication bypasses.");
                        }
                        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
                            bypassable = true;
                            resultList.add(new CcaTestResult(true, ccaWorkflowType, ccaCertificateType,
                                    protocolVersion, cipherSuite));
                        } else {
                            resultList.add(new CcaTestResult(false, ccaWorkflowType, ccaCertificateType,
                                    protocolVersion, cipherSuite));
                        }
                    }
                }
            }
        }
        return new CcaResult(bypassable ? TestResult.TRUE : TestResult.FALSE, resultList);
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.getResult(AnalyzedProperty.SUPPORTS_CCA) == TestResult.TRUE;
    }

    @Override
    public void adjustConfig(SiteReport report) {

    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new CcaResult(TestResult.COULD_NOT_TEST, null);
    }

}
