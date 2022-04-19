/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
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
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.LinkedList;

/**
 * Test the servers Hello Retry Request
 */
public class HelloRetryProbe extends TlsProbe<ServerScannerConfig, ServerReport> {

    private TestResult sendsHelloRetryRequest = TestResults.FALSE;
    private TestResult issuesCookie = TestResults.FALSE;
    private NamedGroup serversChosenGroup = null;

    public HelloRetryProbe(ServerScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.HELLO_RETRY, scannerConfig);
        super.register(TlsAnalyzedProperty.ISSUES_COOKIE_IN_HELLO_RETRY);
        super.register(TlsAnalyzedProperty.SENDS_HELLO_RETRY_REQUEST);
    }

    @Override
    public void executeTest() {
        testHelloRetry();
    }

    @Override
    protected Requirement getRequirements(ServerReport report) {
        return new ProbeRequirement(report).requireAnalyzedProperties(TlsAnalyzedProperty.SUPPORTS_TLS_1_3)
            .requireProbeTypes(TlsProbeType.PROTOCOL_VERSION);
    }

    @Override
    public HelloRetryProbe getCouldNotExecuteResult() {
        this.sendsHelloRetryRequest = this.issuesCookie = TestResults.COULD_NOT_TEST;
        return this;
    }

    @Override
    public void adjustConfig(ServerReport report) {
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
            sendsHelloRetryRequest = TestResults.TRUE;
            serversChosenGroup = state.getTlsContext().getSelectedGroup();
            if (((ServerHelloMessage) WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO,
                state.getWorkflowTrace())).containsExtension(ExtensionType.COOKIE)) {
                issuesCookie = TestResults.TRUE;
            }
        }
    }

    @Override
    protected void mergeData(ServerReport report) {
        if (this.issuesCookie != null)
            super.put(TlsAnalyzedProperty.ISSUES_COOKIE_IN_HELLO_RETRY, this.issuesCookie);
        else
            super.put(TlsAnalyzedProperty.ISSUES_COOKIE_IN_HELLO_RETRY, TestResults.ERROR_DURING_TEST);
        if (sendsHelloRetryRequest != null)
            super.put(TlsAnalyzedProperty.SENDS_HELLO_RETRY_REQUEST, this.sendsHelloRetryRequest);
        else
            super.put(TlsAnalyzedProperty.SENDS_HELLO_RETRY_REQUEST, TestResults.ERROR_DURING_TEST);
        report.setHelloRetryRequestSelectedNamedGroup(this.serversChosenGroup);
    }
}
