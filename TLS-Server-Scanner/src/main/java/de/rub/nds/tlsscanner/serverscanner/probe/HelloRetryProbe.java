/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.HelloRetryResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import java.util.LinkedList;

/**
 * Test the servers Hello Retry Request
 */
public class HelloRetryProbe extends TlsProbe {

    private TestResult sendsHelloRetryRequest = TestResult.FALSE;
    private TestResult issuesCookie = TestResult.FALSE;

    public HelloRetryProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.HELLO_RETRY, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            testHelloRetry();
            return new HelloRetryResult(sendsHelloRetryRequest, issuesCookie);
        } catch (Exception E) {
            LOGGER.error("Could not test for Cookie in Hello Retry :" + E.getMessage());
            return new HelloRetryResult(null, null);
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if (!report.isProbeAlreadyExecuted(ProbeType.PROTOCOL_VERSION)
            || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) != TestResult.TRUE) {
            return false;
        }
        return true;
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new HelloRetryResult(null, null);
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    private void testHelloRetry() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(CipherSuite.getImplementedTls13CipherSuites());
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS13);
        tlsConfig.setSupportedVersions(ProtocolVersion.TLS13);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        tlsConfig.setDefaultClientNamedGroups(NamedGroup.getImplemented());
        // enforce HRR by sending empty key share
        tlsConfig.setDefaultClientKeyShareNamedGroups(new LinkedList<>());
        tlsConfig.setAddECPointFormatExtension(false);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddSupportedVersionsExtension(true);
        tlsConfig.setAddKeyShareExtension(true);
        tlsConfig.setUseFreshRandom(true);
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(
            SignatureAndHashAlgorithm.getTls13SignatureAndHashAlgorithms());
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())
            && ((ServerHelloMessage) WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO,
                state.getWorkflowTrace())).isTls13HelloRetryRequest()) {
            sendsHelloRetryRequest = TestResult.TRUE;
            if (((ServerHelloMessage) WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO,
                state.getWorkflowTrace())).containsExtension(ExtensionType.COOKIE)) {
                issuesCookie = TestResult.TRUE;
            }
        }
    }

}
