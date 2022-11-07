/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.ResumptionResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class ResumptionProbe
        extends TlsServerProbe<ConfigSelector, ServerReport, ResumptionResult> {

    private Set<CipherSuite> supportedSuites;
    private TestResult supportsDtlsCookieExchangeInResumption;
    private TestResult supportsDtlsCookieExchangeInTicketResumption;
    private TestResult respectsPskModes;

    public ResumptionProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.RESUMPTION, configSelector);
    }

    @Override
    public ResumptionResult executeTest() {
        this.respectsPskModes = TestResults.TRUE;
        if (configSelector.getScannerConfig().getDtlsDelegate().isDTLS()) {
            supportsDtlsCookieExchangeInResumption = getSupportsDtlsCookieExchangeInResumption();
            supportsDtlsCookieExchangeInTicketResumption =
                    getSupportsDtlsCookieExchangeInSessionTicketResumption();
            return new ResumptionResult(
                    getSupportsSessionResumption(),
                    getSupportsSessionTicketResumption(),
                    TestResults.NOT_TESTED_YET,
                    TestResults.NOT_TESTED_YET,
                    TestResults.NOT_TESTED_YET,
                    TestResults.NOT_TESTED_YET,
                    supportsDtlsCookieExchangeInResumption,
                    supportsDtlsCookieExchangeInTicketResumption,
                    respectsPskModes);
        } else {
            supportsDtlsCookieExchangeInResumption = TestResults.NOT_TESTED_YET;
            supportsDtlsCookieExchangeInTicketResumption = TestResults.NOT_TESTED_YET;
            return new ResumptionResult(
                    getSupportsSessionResumption(),
                    getSupportsSessionTicketResumption(),
                    getIssuesTls13SessionTicket(),
                    getSupportsTls13Psk(PskKeyExchangeMode.PSK_DHE_KE),
                    getSupportsTls13Psk(PskKeyExchangeMode.PSK_KE),
                    getSupports0rtt(),
                    supportsDtlsCookieExchangeInResumption,
                    supportsDtlsCookieExchangeInTicketResumption,
                    respectsPskModes);
        }
    }

    private TestResult getSupportsDtlsCookieExchangeInResumption() {
        try {
            Config tlsConfig = configSelector.getBaseConfig();
            tlsConfig.setDefaultClientSupportedCipherSuites(new ArrayList<>(supportedSuites));
            WorkflowTrace trace =
                    new WorkflowConfigurationFactory(tlsConfig)
                            .createWorkflowTrace(
                                    WorkflowTraceType.DYNAMIC_HANDSHAKE,
                                    tlsConfig.getDefaultRunningMode());
            addAlertToTrace(trace);
            trace.addTlsAction(new ResetConnectionAction());
            trace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
            trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage(tlsConfig)));
            State state = new State(tlsConfig, trace);
            executeState(state);
            return state.getWorkflowTrace().executedAsPlanned()
                    ? TestResults.TRUE
                    : TestResults.FALSE;
        } catch (Exception e) {
            if (e.getCause() instanceof InterruptedException) {
                LOGGER.error("Timeout on " + getProbeName());
                throw new RuntimeException(e);
            } else {
                LOGGER.error("Could not test for support for Tls13PskDhe");
            }
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private TestResult getSupportsSessionResumption() {
        try {
            if (configSelector.foundWorkingConfig()) {
                Config tlsConfig = configSelector.getBaseConfig();
                tlsConfig.setDefaultClientSupportedCipherSuites(new ArrayList<>(supportedSuites));
                WorkflowTrace trace =
                        new WorkflowConfigurationFactory(tlsConfig)
                                .createWorkflowTrace(
                                        WorkflowTraceType.DYNAMIC_HANDSHAKE,
                                        tlsConfig.getDefaultRunningMode());
                addAlertToTrace(trace);
                trace.addTlsAction(new ResetConnectionAction());
                tlsConfig.setDtlsCookieExchange(
                        supportsDtlsCookieExchangeInResumption == TestResults.TRUE);
                trace.addTlsActions(
                        new WorkflowConfigurationFactory(tlsConfig)
                                .createWorkflowTrace(
                                        WorkflowTraceType.RESUMPTION,
                                        tlsConfig.getDefaultRunningMode())
                                .getTlsActions());
                State state = new State(tlsConfig, trace);
                executeState(state);
                return state.getWorkflowTrace().executedAsPlanned() == true
                        ? TestResults.TRUE
                        : TestResults.FALSE;
            } else {
                return TestResults.FALSE;
            }
        } catch (Exception e) {
            if (e.getCause() instanceof InterruptedException) {
                LOGGER.error("Timeout on " + getProbeName());
                throw new RuntimeException(e);
            } else {
                LOGGER.error("Could not test for support for SessionResumption");
            }
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private TestResult getSupportsDtlsCookieExchangeInSessionTicketResumption() {
        try {
            Config tlsConfig = configSelector.getBaseConfig();
            tlsConfig.setDefaultClientSupportedCipherSuites(new ArrayList<>(supportedSuites));
            tlsConfig.setAddSessionTicketTLSExtension(true);
            WorkflowTrace trace =
                    new WorkflowConfigurationFactory(tlsConfig)
                            .createWorkflowTrace(
                                    WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
            trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
            trace.addTlsAction(
                    new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
            trace.addTlsAction(
                    new ReceiveAction(
                            new NewSessionTicketMessage(),
                            new ChangeCipherSpecMessage(),
                            new FinishedMessage()));
            addAlertToTrace(trace);
            trace.addTlsAction(new ResetConnectionAction());
            trace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
            trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage(tlsConfig)));
            State state = new State(tlsConfig, trace);
            executeState(state);
            return state.getWorkflowTrace().executedAsPlanned()
                    ? TestResults.TRUE
                    : TestResults.FALSE;
        } catch (Exception e) {
            if (e.getCause() instanceof InterruptedException) {
                LOGGER.error("Timeout on " + getProbeName());
                throw new RuntimeException(e);
            } else {
                LOGGER.error(
                        "Could not test for support for dtls cookie exchange in SessionTicketResumption");
            }
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private TestResult getSupportsSessionTicketResumption() {
        try {
            if (configSelector.foundWorkingConfig()) {
                Config tlsConfig = configSelector.getBaseConfig();
                tlsConfig.setDefaultClientSupportedCipherSuites(new ArrayList<>(supportedSuites));
                tlsConfig.setAddSessionTicketTLSExtension(true);
                WorkflowTrace trace =
                        new WorkflowConfigurationFactory(tlsConfig)
                                .createWorkflowTrace(
                                        WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
                trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                trace.addTlsAction(
                        new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                trace.addTlsAction(
                        new ReceiveAction(
                                new NewSessionTicketMessage(),
                                new ChangeCipherSpecMessage(),
                                new FinishedMessage()));
                addAlertToTrace(trace);
                trace.addTlsAction(new ResetConnectionAction());
                tlsConfig.setDtlsCookieExchange(
                        supportsDtlsCookieExchangeInResumption == TestResults.TRUE);
                trace.addTlsActions(
                        new WorkflowConfigurationFactory(tlsConfig)
                                .createWorkflowTrace(
                                        WorkflowTraceType.RESUMPTION,
                                        tlsConfig.getDefaultRunningMode())
                                .getTlsActions());
                State state = new State(tlsConfig, trace);
                executeState(state);
                return state.getWorkflowTrace().executedAsPlanned() == true
                        ? TestResults.TRUE
                        : TestResults.FALSE;
            } else {
                return TestResults.FALSE;
            }
        } catch (Exception e) {
            if (e.getCause() instanceof InterruptedException) {
                LOGGER.error("Timeout on " + getProbeName());
                throw new RuntimeException(e);
            } else {
                LOGGER.error("Could not test for support for SessionTicketResumption");
            }
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private TestResult isKeyShareExtensionNegotiated(State state) {
        List<HandshakeMessage> handshakes =
                WorkflowTraceUtil.getAllReceivedHandshakeMessages(state.getWorkflowTrace());
        List<ServerHelloMessage> hellos =
                handshakes.stream()
                        .filter(message -> message instanceof ServerHelloMessage)
                        .map(message -> (ServerHelloMessage) message)
                        .collect(Collectors.toList());
        if (hellos.size() < 2) {
            return TestResults.COULD_NOT_TEST;
        }
        ServerHelloMessage second = hellos.get(1);
        return second.containsExtension(ExtensionType.KEY_SHARE)
                ? TestResults.TRUE
                : TestResults.FALSE;
    }

    private TestResult getSupportsTls13Psk(PskKeyExchangeMode exchangeMode) {
        try {
            if (configSelector.foundWorkingTls13Config()) {
                Config tlsConfig = configSelector.getTls13BaseConfig();
                List<PskKeyExchangeMode> pskKex = new LinkedList<>();
                pskKex.add(exchangeMode);
                tlsConfig.setPSKKeyExchangeModes(pskKex);
                tlsConfig.setAddPSKKeyExchangeModesExtension(true);
                tlsConfig.setAddPreSharedKeyExtension(true);
                tlsConfig.setWorkflowTraceType(WorkflowTraceType.FULL_TLS13_PSK);
                State state = new State(tlsConfig);
                executeState(state);

                MessageAction lastRcv =
                        (MessageAction) state.getWorkflowTrace().getLastReceivingAction();
                if (lastRcv.executedAsPlanned()) {
                    // Check PSK Modes
                    TestResult keyShareExtensionNegotiated = isKeyShareExtensionNegotiated(state);
                    TestResult keyShareRequired =
                            TestResults.of(exchangeMode.equals(PskKeyExchangeMode.PSK_DHE_KE));
                    if (!keyShareExtensionNegotiated.equals(keyShareRequired)) {
                        if (!TestResults.COULD_NOT_TEST.equals(keyShareExtensionNegotiated)) {
                            respectsPskModes = TestResults.FALSE;
                        }
                    }
                    return TestResults.TRUE;
                }
            }
            return TestResults.FALSE;
        } catch (Exception e) {
            if (e.getCause() instanceof InterruptedException) {
                LOGGER.error("Timeout on " + getProbeName());
                throw new RuntimeException(e);
            } else {
                LOGGER.error("Could not test for support for Tls13Psk (" + exchangeMode + ")");
            }
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private TestResult getSupports0rtt() {
        try {
            if (configSelector.foundWorkingTls13Config()) {
                Config tlsConfig = configSelector.getTls13BaseConfig();
                tlsConfig.setAddPSKKeyExchangeModesExtension(true);
                tlsConfig.setAddPreSharedKeyExtension(true);
                tlsConfig.setAddEarlyDataExtension(true);
                tlsConfig.setWorkflowTraceType(WorkflowTraceType.FULL_ZERO_RTT);
                State state = new State(tlsConfig);
                executeState(state);

                EncryptedExtensionsMessage encExt =
                        state.getWorkflowTrace()
                                .getLastReceivedMessage(EncryptedExtensionsMessage.class);
                if (encExt != null && encExt.containsExtension(ExtensionType.EARLY_DATA)) {
                    return TestResults.TRUE;
                }
            }
            return TestResults.FALSE;
        } catch (Exception e) {
            if (e.getCause() instanceof InterruptedException) {
                LOGGER.error("Timeout on " + getProbeName());
                throw new RuntimeException(e);
            } else {
                LOGGER.error("Could not test for support for Tls13PskDhe");
            }
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private TestResult getIssuesTls13SessionTicket() {
        try {
            if (configSelector.foundWorkingTls13Config()) {
                Config tlsConfig = configSelector.getTls13BaseConfig();
                List<PskKeyExchangeMode> pskKex = new LinkedList<>();
                pskKex.add(PskKeyExchangeMode.PSK_DHE_KE);
                pskKex.add(PskKeyExchangeMode.PSK_KE);
                tlsConfig.setPSKKeyExchangeModes(pskKex);
                tlsConfig.setAddPSKKeyExchangeModesExtension(true);
                tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HANDSHAKE);
                State state = new State(tlsConfig);
                state.getWorkflowTrace()
                        .addTlsAction(
                                new ReceiveAction(
                                        tlsConfig.getDefaultClientConnection().getAlias(),
                                        new NewSessionTicketMessage(false)));
                executeState(state);

                if (WorkflowTraceUtil.didReceiveMessage(
                        HandshakeMessageType.NEW_SESSION_TICKET, state.getWorkflowTrace())) {
                    return TestResults.TRUE;
                }
            }
            return TestResults.FALSE;
        } catch (Exception e) {
            if (e.getCause() instanceof InterruptedException) {
                LOGGER.error("Timeout on " + getProbeName());
                throw new RuntimeException(e);
            } else {
                LOGGER.error("Could not test for support for Tls13SessionTickets");
            }
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private void addAlertToTrace(WorkflowTrace trace) {
        AlertMessage alert = new AlertMessage();
        alert.setConfig(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);
        trace.addTlsAction(new SendAction(alert));
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return report.getCipherSuites() != null && (!report.getCipherSuites().isEmpty());
    }

    @Override
    public void adjustConfig(ServerReport report) {
        supportedSuites = report.getCipherSuites();
        supportedSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        supportedSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
    }

    @Override
    public ResumptionResult getCouldNotExecuteResult() {
        return new ResumptionResult(
                TestResults.COULD_NOT_TEST,
                TestResults.COULD_NOT_TEST,
                TestResults.COULD_NOT_TEST,
                TestResults.COULD_NOT_TEST,
                TestResults.COULD_NOT_TEST,
                TestResults.COULD_NOT_TEST,
                TestResults.COULD_NOT_TEST,
                TestResults.COULD_NOT_TEST,
                TestResults.COULD_NOT_TEST);
    }
}
