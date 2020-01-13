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
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.CcaResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.report.result.cca.CcaTestResult;

import java.util.LinkedList;
import java.util.List;

public class DebugProbe extends TlsProbe {
    private List<VersionSuiteListPair> versionSuiteListPairsList;

    public DebugProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.CCA, config, 5);
        versionSuiteListPairsList = new LinkedList<>();
    }

    @Override
    public ProbeResult executeTest() {
        CcaCommandConfig ccaConfig = new CcaCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) ccaConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());

        CcaDelegate ccaDelegate = (CcaDelegate) getScannerConfig().getDelegate(CcaDelegate.class);

        /**
         * Add any protocol version (1.0-1.2) to the versions we iterate
         */
        List<ProtocolVersion> desiredVersions = new LinkedList<>();
//        desiredVersions.add(ProtocolVersion.TLS11);
//        desiredVersions.add(ProtocolVersion.TLS10);
        desiredVersions.add(ProtocolVersion.TLS12);



        List<CipherSuite> cipherSuites = new LinkedList<>();

//        cipherSuites.add(CipherSuite.TLS_AES_256_GCM_SHA384);
//        cipherSuites.add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
//        cipherSuites.add(CipherSuite.TLS_AES_128_GCM_SHA256);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
//        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
//        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
//        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384);
//        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
//        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
//        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
//        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
//        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384);
//        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
//        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256);
//        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
//        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
//        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
//        cipherSuites.add(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
//        cipherSuites.add(CipherSuite.TLS_RSA_WITH_DES_CBC_SHA);
        cipherSuites.addAll(CipherSuite.getImplemented());

        List<CcaTestResult> resultList = new LinkedList<>();
        Boolean bypassable = false;
//        for (CcaWorkflowType ccaWorkflowType : CcaWorkflowType.values()) {
        CcaWorkflowType ccaWorkflowType = CcaWorkflowType.CRT_CKE_VRFY_CCS_FIN;
        CcaCertificateType ccaCertificateType = CcaCertificateType.ROOTv3_CAv3_LEAFv1_nLEAF_RSAv3;
//            for (CcaCertificateType ccaCertificateType : CcaCertificateType.values()) {
        for (ProtocolVersion protocolVersion : desiredVersions) {
            // Dummy for output since I do not iterate Ciphersuites
            CipherSuite cipherSuite = CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA;
            CertificateMessage certificateMessage = null;
            Config tlsConfig = ccaConfig.createConfig();
            tlsConfig.setDefaultClientSupportedCiphersuites(cipherSuites);
            tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
            // Needed for CyaSSL/WolfSSL. The server answers only to client hellos which have Version 1.0 in the Record Protocol
//          tlsConfig.setDefaultSelectedProtocolVersion(ProtocolVersion.TLS10);
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
            try {
                certificateMessage = CcaCertificateGenerator.generateCertificate(ccaDelegate, ccaCertificateType);
            } catch (Exception e) {
                LOGGER.error("Error while generating certificateMessage." + e);
            }
            WorkflowTrace trace = CcaWorkflowGenerator.generateWorkflow(tlsConfig, ccaWorkflowType,
                    certificateMessage);
            ApplicationMessage applicationMessage = new ApplicationMessage();
            trace.addTlsAction(new SendAction(applicationMessage));
            State state = new State(tlsConfig, trace);

            try {
                executeState(state);
            } catch (Exception E) {
                LOGGER.error("Error while testing for client authentication bypasses." + E);
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
        return new CcaResult(bypassable ? TestResult.TRUE : TestResult.FALSE, resultList);
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
       return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {}

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new CcaResult(TestResult.COULD_NOT_TEST, null);
    }

}