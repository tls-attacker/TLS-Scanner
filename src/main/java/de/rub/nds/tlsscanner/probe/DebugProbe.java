/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.attacks.cca.*;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.CcaDelegate;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.rating.TestResult;
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
        CcaDelegate ccaDelegate = (CcaDelegate) getScannerConfig().getDelegate(CcaDelegate.class);

        /**
         * Add any protocol version (1.0-1.2) to the versions we iterate
         */
        List<ProtocolVersion> desiredVersions = new LinkedList<>();
//        desiredVersions.add(ProtocolVersion.TLS11);
//        desiredVersions.add(ProtocolVersion.TLS10);
        desiredVersions.add(ProtocolVersion.TLS12);

        List<CipherSuite> cipherSuites = new LinkedList<>();

//        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
//        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
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
//        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384);
//        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
//        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256);
//        cipherSuites.add(CipherSmasterSecretuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
//        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
//        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);

        List<CcaTestResult> resultList = new LinkedList<>();
        Boolean bypassable = false;
        CcaWorkflowType ccaWorkflowType = CcaWorkflowType.CRT_ECKE_CCS_FIN;

        CipherSuite cipherSuite = CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256;
        cipherSuites.add(cipherSuite);

        CcaCertificateType ccaCertificateType = CcaCertificateType.ROOTv3_CAv3_LEAF_ECv3_KeyAgreement;

        for (ProtocolVersion protocolVersion : desiredVersions) {
            Config tlsConfig = generateConfig();

            tlsConfig.setDefaultClientSupportedCiphersuites(cipherSuites);
            tlsConfig.setHighestProtocolVersion(protocolVersion);
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);

            WorkflowTrace trace = CcaWorkflowGenerator.generateWorkflow(tlsConfig, ccaDelegate, ccaWorkflowType,
                    ccaCertificateType);

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


    private Config generateConfig() {
        Config config = getScannerConfig().createConfig();
        config.setAutoSelectCertificate(false);
        config.setAddServerNameIndicationExtension(true);
        config.setDefaultSelectedProtocolVersion(ProtocolVersion.TLS10);
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);

        config.setQuickReceive(true);
        config.setEarlyStop(true);
        config.setStopActionsAfterIOException(true);
        config.setStopActionsAfterFatal(true);

        return config;
    }
}