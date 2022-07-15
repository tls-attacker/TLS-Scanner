/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.FlushSessionCacheAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.RenegotiationAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.RenegotiationResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.ArrayList;
import java.util.Set;

public class RenegotiationProbe extends TlsServerProbe<ConfigSelector, ServerReport, RenegotiationResult> {

    private Set<CipherSuite> supportedSuites;
    private TestResult supportsDtlsCookieExchangeInRenegotiation;

    public RenegotiationProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.RENEGOTIATION, configSelector);
    }

    @Override
    public RenegotiationResult executeTest() {
        if (configSelector.getScannerConfig().getDtlsDelegate().isDTLS()) {
            supportsDtlsCookieExchangeInRenegotiation = supportsDtlsCookieExchangeInRenegotiation();
        } else {
            supportsDtlsCookieExchangeInRenegotiation = TestResults.NOT_TESTED_YET;
        }
        return new RenegotiationResult(supportsSecureClientRenegotiationExtension(),
            supportsSecureClientRenegotiationCipherSuite(), supportsInsecureClientRenegotiation(),
            vulnerableToRenegotiationAttackExtension(false, true),
            vulnerableToRenegotiationAttackExtension(true, false),
            vulnerableToRenegotiationAttackCipherSuite(false, true),
            vulnerableToRenegotiationAttackCipherSuite(true, false), supportsDtlsCookieExchangeInRenegotiation);
    }

    private TestResult vulnerableToRenegotiationAttackExtension(boolean addExtensionInFirstHandshake,
        boolean addExtensionInSecondHandshake) {
        Config tlsConfig = getBaseConfig();
        tlsConfig.setAddRenegotiationInfoExtension(addExtensionInFirstHandshake);
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, tlsConfig.getDefaultRunningMode());
        trace.addTlsAction(new RenegotiationAction(true));
        trace.addTlsAction(new FlushSessionCacheAction());
        tlsConfig.setAddRenegotiationInfoExtension(addExtensionInSecondHandshake);
        tlsConfig.setDtlsCookieExchange(supportsDtlsCookieExchangeInRenegotiation == TestResults.TRUE);
        trace.addTlsActions(new WorkflowConfigurationFactory(tlsConfig)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, tlsConfig.getDefaultRunningMode())
            .getTlsActions());
        State state = new State(tlsConfig, trace);
        executeState(state);
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace)) {
            return TestResults.COULD_NOT_TEST;
        }
        return state.getWorkflowTrace().executedAsPlanned() ? TestResults.TRUE : TestResults.FALSE;
    }

    private TestResult vulnerableToRenegotiationAttackCipherSuite(boolean addCipherSuiteInFirstHandshake,
        boolean addCipherSuiteInSecondHandshake) {
        Config tlsConfig = getBaseConfig();
        tlsConfig.setAddRenegotiationInfoExtension(addCipherSuiteInFirstHandshake);
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, tlsConfig.getDefaultRunningMode());
        if (addCipherSuiteInFirstHandshake) {
            addRenegotiationCipherSuiteToClientHello(tlsConfig, trace);
        }
        trace.addTlsAction(new RenegotiationAction(true));
        trace.addTlsAction(new FlushSessionCacheAction());
        tlsConfig.setAddRenegotiationInfoExtension(addCipherSuiteInSecondHandshake);
        tlsConfig.setDtlsCookieExchange(supportsDtlsCookieExchangeInRenegotiation == TestResults.TRUE);
        WorkflowTrace secondHandshake = new WorkflowConfigurationFactory(tlsConfig)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, tlsConfig.getDefaultRunningMode());
        if (addCipherSuiteInSecondHandshake) {
            addRenegotiationCipherSuiteToClientHello(tlsConfig, secondHandshake);
        }
        trace.addTlsActions(secondHandshake.getTlsActions());
        State state = new State(tlsConfig, trace);
        executeState(state);
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace)) {
            return TestResults.COULD_NOT_TEST;
        }
        return state.getWorkflowTrace().executedAsPlanned() ? TestResults.TRUE : TestResults.FALSE;
    }

    private void addRenegotiationCipherSuiteToClientHello(Config tlsConfig, WorkflowTrace trace) {
        for (SendingAction action : WorkflowTraceUtil.getSendingActionsForMessage(HandshakeMessageType.CLIENT_HELLO,
            trace)) {
            action.getSendMessages().clear();
            ClientHelloMessage clientHelloMessage = new ClientHelloMessage(tlsConfig);
            clientHelloMessage
                .setCipherSuites(Modifiable.insert(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV.getByteValue(), 0));
            action.getSendMessages().add(clientHelloMessage);
        }
    }

    private TestResult supportsSecureClientRenegotiationExtension() {
        Config tlsConfig = getBaseConfig();
        tlsConfig.setAddRenegotiationInfoExtension(true);
        State state = new State(tlsConfig);
        if (tlsConfig.getHighestProtocolVersion().isDTLS()) {
            WorkflowTrace trace =
                getDtlsRenegotiationTrace(tlsConfig, supportsDtlsCookieExchangeInRenegotiation == TestResults.TRUE);
            state = new State(tlsConfig, trace);
        }
        executeState(state);
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return TestResults.COULD_NOT_TEST;
        }
        return state.getWorkflowTrace().executedAsPlanned() ? TestResults.TRUE : TestResults.FALSE;
    }

    private TestResult supportsSecureClientRenegotiationCipherSuite() {
        Config tlsConfig = getBaseConfig();
        tlsConfig.setAddRenegotiationInfoExtension(false);
        tlsConfig.getDefaultClientSupportedCipherSuites().add(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        State state = new State(tlsConfig);
        if (tlsConfig.getHighestProtocolVersion().isDTLS()) {
            WorkflowTrace trace =
                getDtlsRenegotiationTrace(tlsConfig, supportsDtlsCookieExchangeInRenegotiation == TestResults.TRUE);
            state = new State(tlsConfig, trace);
        }
        executeState(state);
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return TestResults.COULD_NOT_TEST;
        }
        return state.getWorkflowTrace().executedAsPlanned() ? TestResults.TRUE : TestResults.FALSE;
    }

    private TestResult supportsInsecureClientRenegotiation() {
        Config tlsConfig = getBaseConfig();
        tlsConfig.setAddRenegotiationInfoExtension(false);
        State state = new State(tlsConfig);
        if (tlsConfig.getHighestProtocolVersion().isDTLS()) {
            WorkflowTrace trace =
                getDtlsRenegotiationTrace(tlsConfig, supportsDtlsCookieExchangeInRenegotiation == TestResults.TRUE);
            state = new State(tlsConfig, trace);
        }
        executeState(state);
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return TestResults.COULD_NOT_TEST;
        }
        return state.getWorkflowTrace().executedAsPlanned() ? TestResults.TRUE : TestResults.FALSE;
    }

    private WorkflowTrace getDtlsRenegotiationTrace(Config tlsConfig, boolean renegotiationWithCookieExchange) {
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, tlsConfig.getDefaultRunningMode());
        trace.addTlsAction(new RenegotiationAction());
        trace.addTlsAction(new FlushSessionCacheAction());
        tlsConfig.setDtlsCookieExchange(renegotiationWithCookieExchange);
        trace.addTlsActions(new WorkflowConfigurationFactory(tlsConfig)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, tlsConfig.getDefaultRunningMode())
            .getTlsActions());
        return trace;
    }

    private TestResult supportsDtlsCookieExchangeInRenegotiation() {
        Config tlsConfig = getBaseConfig();
        tlsConfig.setAddRenegotiationInfoExtension(true);
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, tlsConfig.getDefaultRunningMode());
        trace.addTlsAction(new RenegotiationAction());
        trace.addTlsAction(new FlushSessionCacheAction());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
        State state = new State(tlsConfig, trace);
        executeState(state);
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return TestResults.COULD_NOT_TEST;
        }
        return state.getWorkflowTrace().executedAsPlanned() ? TestResults.FALSE : TestResults.TRUE;
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return (report.getCipherSuites() != null && !report.getCipherSuites().isEmpty() && !supportsOnlyTls13(report));
    }

    @Override
    public void adjustConfig(ServerReport report) {
        supportedSuites = report.getCipherSuites();
        supportedSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        supportedSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
    }

    @Override
    public RenegotiationResult getCouldNotExecuteResult() {
        return new RenegotiationResult(TestResults.COULD_NOT_TEST, TestResults.COULD_NOT_TEST,
            TestResults.COULD_NOT_TEST, TestResults.COULD_NOT_TEST, TestResults.COULD_NOT_TEST,
            TestResults.COULD_NOT_TEST, TestResults.COULD_NOT_TEST, TestResults.COULD_NOT_TEST);
    }

    /**
     * Used to run the probe with empty CS list if we already know versions before TLS 1.3 are not supported, to avoid
     * stalling of probes that depend on this one
     */
    private boolean supportsOnlyTls13(ServerReport report) {
        return report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_0) != TestResults.TRUE
            && report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_1) != TestResults.TRUE
            && report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_2) != TestResults.TRUE
            && report.getResult(TlsAnalyzedProperty.SUPPORTS_DTLS_1_0) != TestResults.TRUE
            && report.getResult(TlsAnalyzedProperty.SUPPORTS_DTLS_1_2) != TestResults.TRUE;
    }

    private Config getBaseConfig() {
        Config tlsConfig = configSelector.getBaseConfig();
        tlsConfig.setDefaultClientSupportedCipherSuites(new ArrayList<>(supportedSuites));
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_CLIENT_RENEGOTIATION_WITHOUT_RESUMPTION);
        configSelector.repairConfig(tlsConfig);
        return tlsConfig;
    }
}
