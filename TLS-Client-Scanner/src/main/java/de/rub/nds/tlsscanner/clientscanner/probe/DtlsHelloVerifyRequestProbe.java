/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceMutator;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeWriteSequenceNumberAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerCertificateAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;
import java.util.Arrays;

public class DtlsHelloVerifyRequestProbe extends TlsClientProbe {

    private TestResult supportsCookieExchange = TestResults.COULD_NOT_TEST;
    private TestResult acceptsLegacyServerVersionMismatch = TestResults.COULD_NOT_TEST;
    private TestResult acceptsHvrSequenceNumberMismatch = TestResults.COULD_NOT_TEST;
    private TestResult acceptsServerHelloSequenceNumberMismatch = TestResults.COULD_NOT_TEST;
    private TestResult hasClientHelloMismatch = TestResults.COULD_NOT_TEST;
    private TestResult acceptsEmptyCookie = TestResults.COULD_NOT_TEST;

    public DtlsHelloVerifyRequestProbe(
            ParallelExecutor executor, ClientScannerConfig scannerConfig) {
        super(executor, TlsProbeType.DTLS_HELLO_VERIFY_REQUEST, scannerConfig);
        register(
                TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE,
                TlsAnalyzedProperty.ACCEPTS_HVR_LEGACY_SERVER_VERSION_MISMATCH,
                TlsAnalyzedProperty.ACCEPTS_HVR_RECORD_SEQUENCE_NUMBER_MISMATCH,
                TlsAnalyzedProperty.ACCEPTS_SERVER_HELLO_RECORD_SEQUENCE_NUMBER_MISMATCH,
                TlsAnalyzedProperty.HAS_CLIENT_HELLO_MISMATCH,
                TlsAnalyzedProperty.ACCEPTS_EMPTY_COOKIE);
    }

    @Override
    protected void executeTest() {
        supportsCookieExchange = supportsCookieExchange();
        if (supportsCookieExchange == TestResults.TRUE) {
            acceptsLegacyServerVersionMismatch = acceptsLegacyServerVersionMismatch();
            acceptsHvrSequenceNumberMismatch = acceptsHvrSequenceNumberMismatch();
            acceptsServerHelloSequenceNumberMismatch = acceptsServerHelloSequenceNumberMismatch();
            hasClientHelloMismatch = hasClientHelloMismatch();
            acceptsEmptyCookie = acceptsEmptyCookie();
        }
    }

    private TestResult supportsCookieExchange() {
        Config config = scannerConfig.createConfig();
        config.setDtlsCookieExchange(true);
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(WorkflowTraceType.HELLO, RunningModeType.SERVER);
        State state = new State(config, trace);
        executeState(state);
        ClientHelloMessage firstClientHello =
                (ClientHelloMessage)
                        WorkflowTraceResultUtil.getFirstReceivedMessage(
                                trace, HandshakeMessageType.CLIENT_HELLO);
        ClientHelloMessage secondClientHello =
                (ClientHelloMessage)
                        WorkflowTraceResultUtil.getLastReceivedMessage(
                                trace, HandshakeMessageType.CLIENT_HELLO);
        HelloVerifyRequestMessage helloVerifyRequest =
                (HelloVerifyRequestMessage)
                        WorkflowTraceResultUtil.getFirstReceivedMessage(
                                trace, HandshakeMessageType.HELLO_VERIFY_REQUEST);
        if (firstClientHello != secondClientHello
                && secondClientHello
                        .getCookie()
                        .getValue()
                        .equals(helloVerifyRequest.getCookie().getValue())) {
            return TestResults.TRUE;
        }
        return TestResults.FALSE;
    }

    private TestResult acceptsLegacyServerVersionMismatch() {
        Config config = scannerConfig.createConfig();

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(WorkflowTraceType.HELLO, RunningModeType.SERVER);
        HelloVerifyRequestMessage hvrMessage = new HelloVerifyRequestMessage();
        hvrMessage.setProtocolVersion(Modifiable.explicit(ProtocolVersion.DTLS10.getValue()));
        WorkflowTraceMutator.replaceStaticSendingMessage(
                trace, HandshakeMessageType.HELLO_VERIFY_REQUEST, hvrMessage);
        ServerHelloMessage serverHello = new ServerHelloMessage(config);
        serverHello.setProtocolVersion(Modifiable.explicit(ProtocolVersion.DTLS12.getValue()));
        WorkflowTraceMutator.replaceStaticSendingMessage(
                trace, HandshakeMessageType.SERVER_HELLO, serverHello);
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

        State state = new State(config, trace);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult acceptsHvrSequenceNumberMismatch() {
        Config config = scannerConfig.createConfig();

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultServerConnection());
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        trace.addTlsAction(new ChangeWriteSequenceNumberAction(5));
        trace.addTlsAction(new SendAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new ServerHelloMessage(config)));
        trace.addTlsAction(new SendDynamicServerCertificateAction());
        trace.addTlsAction(new SendDynamicServerKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ServerHelloDoneMessage()));
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

        State state = new State(config, trace);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult acceptsServerHelloSequenceNumberMismatch() {
        Config config = scannerConfig.createConfig();

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultServerConnection());
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        trace.addTlsAction(new ChangeWriteSequenceNumberAction(5));
        trace.addTlsAction(new SendAction(new ServerHelloMessage(config)));
        trace.addTlsAction(new SendDynamicServerCertificateAction());
        trace.addTlsAction(new SendDynamicServerKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ServerHelloDoneMessage()));
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

        State state = new State(config, trace);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult hasClientHelloMismatch() {
        Config config = scannerConfig.createConfig();

        WorkflowTrace trace = new WorkflowTrace();
        ReceiveAction firstReceiveAction = new ReceiveAction(new ClientHelloMessage());
        trace.addTlsAction(firstReceiveAction);
        trace.addTlsAction(new SendAction(new HelloVerifyRequestMessage()));
        ReceiveAction secondReceiveAction = new ReceiveAction(new ClientHelloMessage());
        trace.addTlsAction(secondReceiveAction);

        State state = new State(config, trace);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            ClientHelloMessage firstClientHello =
                    (ClientHelloMessage) firstReceiveAction.getReceivedMessages().get(0);
            ClientHelloMessage secondClientHello =
                    (ClientHelloMessage) secondReceiveAction.getReceivedMessages().get(0);
            boolean versionMatch =
                    Arrays.equals(
                            firstClientHello.getProtocolVersion().getValue(),
                            secondClientHello.getProtocolVersion().getValue());
            boolean randomMatch =
                    Arrays.equals(
                            firstClientHello.getRandom().getValue(),
                            secondClientHello.getRandom().getValue());
            boolean sessionIdMatch =
                    Arrays.equals(
                            firstClientHello.getSessionId().getValue(),
                            secondClientHello.getSessionId().getValue());
            boolean cipherSuitesMatch =
                    Arrays.equals(
                            firstClientHello.getCipherSuites().getValue(),
                            secondClientHello.getCipherSuites().getValue());
            boolean compressionsMatch =
                    Arrays.equals(
                            firstClientHello.getCompressions().getValue(),
                            secondClientHello.getCompressions().getValue());
            if (versionMatch
                    && randomMatch
                    && sessionIdMatch
                    && cipherSuitesMatch
                    && compressionsMatch) {
                return TestResults.FALSE;
            } else {
                return TestResults.TRUE;
            }
        } else {
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private TestResult acceptsEmptyCookie() {
        Config config = scannerConfig.createConfig();
        config.setDtlsDefaultCookieLength(0);

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(WorkflowTraceType.HELLO, RunningModeType.SERVER);
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

        State state = new State(config, trace);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    @Override
    public void adjustConfig(ClientReport report) {}

    @Override
    protected void mergeData(ClientReport report) {
        put(TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE, supportsCookieExchange);
        put(
                TlsAnalyzedProperty.ACCEPTS_HVR_LEGACY_SERVER_VERSION_MISMATCH,
                acceptsLegacyServerVersionMismatch);
        put(
                TlsAnalyzedProperty.ACCEPTS_HVR_RECORD_SEQUENCE_NUMBER_MISMATCH,
                acceptsHvrSequenceNumberMismatch);
        put(
                TlsAnalyzedProperty.ACCEPTS_SERVER_HELLO_RECORD_SEQUENCE_NUMBER_MISMATCH,
                acceptsServerHelloSequenceNumberMismatch);
        put(TlsAnalyzedProperty.HAS_CLIENT_HELLO_MISMATCH, hasClientHelloMismatch);
        put(TlsAnalyzedProperty.ACCEPTS_EMPTY_COOKIE, acceptsEmptyCookie);
    }

    @Override
    public Requirement<ClientReport> getRequirements() {
        return new ProtocolTypeTrueRequirement<>(ProtocolType.DTLS);
    }
}
