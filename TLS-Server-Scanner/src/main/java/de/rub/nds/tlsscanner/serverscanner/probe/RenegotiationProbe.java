/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
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
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.RenegotiationResult;
import java.util.ArrayList;
import java.util.Set;

public class RenegotiationProbe extends TlsProbe {

    private Set<CipherSuite> supportedSuites;
    private TestResult supportsDtlsCookieExchangeInRenegotiation;

    public RenegotiationProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.RENEGOTIATION, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            if (getScannerConfig().getDtlsDelegate().isDTLS()) {
                supportsDtlsCookieExchangeInRenegotiation = supportsDtlsCookieExchangeInRenegotiation();
            } else {
                supportsDtlsCookieExchangeInRenegotiation = TestResult.NOT_TESTED_YET;
            }
            return new RenegotiationResult(supportsSecureClientRenegotiationExtension(),
                supportsSecureClientRenegotiationCipherSuite(), supportsInsecureClientRenegotiation(),
                vulnerableToRenegotiationAttackExtension(false, true),
                vulnerableToRenegotiationAttackExtension(true, false),
                vulnerableToRenegotiationAttackCipherSuite(false, true),
                vulnerableToRenegotiationAttackCipherSuite(true, false), supportsDtlsCookieExchangeInRenegotiation);
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new RenegotiationResult(TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST,
                TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST,
                TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST);
        }
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
        tlsConfig.setDtlsCookieExchange(supportsDtlsCookieExchangeInRenegotiation == TestResult.TRUE);
        trace.addTlsActions(new WorkflowConfigurationFactory(tlsConfig)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, tlsConfig.getDefaultRunningMode())
            .getTlsActions());
        State state = new State(tlsConfig, trace);
        executeState(state);
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace)) {
            return TestResult.COULD_NOT_TEST;
        }
        return state.getWorkflowTrace().executedAsPlanned() ? TestResult.TRUE : TestResult.FALSE;
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
        tlsConfig.setDtlsCookieExchange(supportsDtlsCookieExchangeInRenegotiation == TestResult.TRUE);
        WorkflowTrace secondHandshake = new WorkflowConfigurationFactory(tlsConfig)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, tlsConfig.getDefaultRunningMode());
        if (addCipherSuiteInSecondHandshake) {
            addRenegotiationCipherSuiteToClientHello(tlsConfig, secondHandshake);
        }
        trace.addTlsActions(secondHandshake.getTlsActions());
        State state = new State(tlsConfig, trace);
        executeState(state);
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace)) {
            return TestResult.COULD_NOT_TEST;
        }
        return state.getWorkflowTrace().executedAsPlanned() ? TestResult.TRUE : TestResult.FALSE;
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
                getDtlsRenegotiationTrace(tlsConfig, supportsDtlsCookieExchangeInRenegotiation == TestResult.TRUE);
            state = new State(tlsConfig, trace);
        }
        executeState(state);
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return TestResult.COULD_NOT_TEST;
        }
        return state.getWorkflowTrace().executedAsPlanned() ? TestResult.TRUE : TestResult.FALSE;
    }

    private TestResult supportsSecureClientRenegotiationCipherSuite() {
        Config tlsConfig = getBaseConfig();
        tlsConfig.setAddRenegotiationInfoExtension(false);
        tlsConfig.getDefaultClientSupportedCipherSuites().add(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        State state = new State(tlsConfig);
        if (tlsConfig.getHighestProtocolVersion().isDTLS()) {
            WorkflowTrace trace =
                getDtlsRenegotiationTrace(tlsConfig, supportsDtlsCookieExchangeInRenegotiation == TestResult.TRUE);
            state = new State(tlsConfig, trace);
        }
        executeState(state);
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return TestResult.COULD_NOT_TEST;
        }
        return state.getWorkflowTrace().executedAsPlanned() ? TestResult.TRUE : TestResult.FALSE;
    }

    private TestResult supportsInsecureClientRenegotiation() {
        Config tlsConfig = getBaseConfig();
        tlsConfig.setAddRenegotiationInfoExtension(false);
        State state = new State(tlsConfig);
        if (tlsConfig.getHighestProtocolVersion().isDTLS()) {
            WorkflowTrace trace =
                getDtlsRenegotiationTrace(tlsConfig, supportsDtlsCookieExchangeInRenegotiation == TestResult.TRUE);
            state = new State(tlsConfig, trace);
        }
        executeState(state);
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return TestResult.COULD_NOT_TEST;
        }
        return state.getWorkflowTrace().executedAsPlanned() ? TestResult.TRUE : TestResult.FALSE;
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
            return TestResult.COULD_NOT_TEST;
        }
        return state.getWorkflowTrace().executedAsPlanned() ? TestResult.FALSE : TestResult.TRUE;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return (report.getCipherSuites() != null && (report.getCipherSuites().size() > 0 || supportsOnlyTls13(report)));
    }

    @Override
    public void adjustConfig(SiteReport report) {
        supportedSuites = report.getCipherSuites();
        supportedSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        supportedSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new RenegotiationResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST,
            TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST,
            TestResult.COULD_NOT_TEST);
    }

    /**
     * Used to run the probe with empty CS list if we already know versions before TLS 1.3 are not supported, to avoid
     * stalling of probes that depend on this one
     */
    private boolean supportsOnlyTls13(SiteReport report) {
        return report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0) == TestResult.FALSE
            && report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1) == TestResult.FALSE
            && report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2) == TestResult.FALSE
            && report.getResult(AnalyzedProperty.SUPPORTS_DTLS_1_0) == TestResult.FALSE
            && report.getResult(AnalyzedProperty.SUPPORTS_DTLS_1_2) == TestResult.FALSE;
    }

    private Config getBaseConfig() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setDefaultClientSupportedCipherSuites(new ArrayList<>(supportedSuites));
        tlsConfig.setDefaultSelectedCipherSuite(tlsConfig.getDefaultClientSupportedCipherSuites().get(0));
        tlsConfig.setDefaultClientNamedGroups(NamedGroup.getImplemented());
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_CLIENT_RENEGOTIATION_WITHOUT_RESUMPTION);
        boolean containsEc = false;
        for (CipherSuite suite : tlsConfig.getDefaultClientSupportedCipherSuites()) {
            KeyExchangeAlgorithm keyExchangeAlgorithm = AlgorithmResolver.getKeyExchangeAlgorithm(suite);
            if (keyExchangeAlgorithm != null && keyExchangeAlgorithm.name().toUpperCase().contains("EC")) {
                containsEc = true;
                break;
            }
        }
        tlsConfig.setAddECPointFormatExtension(containsEc);
        tlsConfig.setAddEllipticCurveExtension(containsEc);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setStopReceivingAfterWarning(true);
        tlsConfig.setStopActionsAfterWarning(true);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setQuickReceive(true);
        return tlsConfig;
    }
}
