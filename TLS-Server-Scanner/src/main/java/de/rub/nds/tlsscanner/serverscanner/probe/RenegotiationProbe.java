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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.RenegotiationResult;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class RenegotiationProbe extends TlsProbe {

    private Set<CipherSuite> supportedSuites;
    private TestResult supportsRenegotiationExtension;

    public RenegotiationProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.RENEGOTIATION, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            TestResult supportsSecureRenegotiationExtension;
            if (supportsRenegotiationExtension == TestResult.TRUE) {
                supportsSecureRenegotiationExtension = supportsSecureClientRenegotiationExtension();
            } else {
                supportsSecureRenegotiationExtension = TestResult.FALSE;
            }
            TestResult supportsSecureRenegotiationCipherSuite = supportsSecureClientRenegotiationCipherSuite();
            TestResult supportsInsecureRenegotiation = supportsInsecureClientRenegotiation();
            TestResult vulnerableToRenegotiationAttackExtension = vulnerableToRenegotiationAttackExtension();
            TestResult vulnerableToRenegotiationAttackCipherSuite = vulnerableToRenegotiationAttackCipherSuite();
            return new RenegotiationResult(supportsSecureRenegotiationExtension, supportsSecureRenegotiationCipherSuite,
                supportsInsecureRenegotiation, vulnerableToRenegotiationAttackExtension,
                vulnerableToRenegotiationAttackCipherSuite);
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new RenegotiationResult(TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST,
                TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST);
        }
    }

    private TestResult vulnerableToRenegotiationAttackExtension() {
        Config tlsConfig = getBaseConfig();
        tlsConfig.setAddRenegotiationInfoExtension(false);
        WorkflowConfigurationFactory configFactory = new WorkflowConfigurationFactory(tlsConfig);
        WorkflowTrace trace = configFactory.createTlsEntryWorkflowTrace(tlsConfig.getDefaultClientConnection());

        trace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(tlsConfig)));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        tlsConfig.setAddRenegotiationInfoExtension(true);
        trace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(tlsConfig)));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        State state = new State(tlsConfig, trace);
        executeState(state);
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace)) {
            return TestResult.COULD_NOT_TEST;
        }
        return state.getWorkflowTrace().executedAsPlanned() ? TestResult.TRUE : TestResult.FALSE;
    }

    private TestResult vulnerableToRenegotiationAttackCipherSuite() {
        Config tlsConfig = getBaseConfig();
        tlsConfig.setAddRenegotiationInfoExtension(false);
        WorkflowConfigurationFactory configFactory = new WorkflowConfigurationFactory(tlsConfig);
        WorkflowTrace trace = configFactory.createTlsEntryWorkflowTrace(tlsConfig.getDefaultClientConnection());

        trace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(tlsConfig)));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        tlsConfig.setAddRenegotiationInfoExtension(true);
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(tlsConfig);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            for (CipherSuite suite : tlsConfig.getDefaultClientSupportedCipherSuites()) {

                outputStream.write(suite.getByteValue());

            }
            outputStream.write(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV.getByteValue());
        } catch (IOException ex) {
            LOGGER.error("Could not write cipher suite value to stream");
        }
        clientHelloMessage.setCipherSuites(Modifiable.explicit(outputStream.toByteArray()));
        trace.addTlsAction(new SendAction(clientHelloMessage));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(tlsConfig)));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        State state = new State(tlsConfig, trace);
        executeState(state);
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace)) {
            return TestResult.COULD_NOT_TEST;
        }
        return state.getWorkflowTrace().executedAsPlanned() ? TestResult.TRUE : TestResult.FALSE;
    }

    private TestResult supportsSecureClientRenegotiationExtension() {
        Config tlsConfig = getBaseConfig();
        tlsConfig.setAddRenegotiationInfoExtension(true);
        State state = new State(tlsConfig);
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
        executeState(state);
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return TestResult.COULD_NOT_TEST;
        }
        return state.getWorkflowTrace().executedAsPlanned() ? TestResult.TRUE : TestResult.FALSE;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return (report.getCipherSuites() != null && (report.getCipherSuites().size() > 0 || supportsOnlyTls13(report)));
    }

    @Override
    public void adjustConfig(SiteReport report) {
        supportedSuites = new HashSet<>();
        supportedSuites.addAll(Arrays.asList(CipherSuite.values()));
        supportedSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        supportedSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        supportsRenegotiationExtension = TestResult.TRUE;
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new RenegotiationResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST,
            TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST);
    }

    /**
     * Used to run the probe with empty CS list if we already know versions before TLS 1.3 are not supported, to avoid
     * stalling of probes that depend on this one
     */
    private boolean supportsOnlyTls13(SiteReport report) {
        return report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0) == TestResult.FALSE
            && report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1) == TestResult.FALSE
            && report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2) == TestResult.FALSE;
    }

    private Config getBaseConfig() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(new ArrayList<>(supportedSuites));
        tlsConfig.setDefaultSelectedCipherSuite(tlsConfig.getDefaultClientSupportedCipherSuites().get(0));
        tlsConfig.setDefaultClientNamedGroups(NamedGroup.getImplemented());

        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
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
        tlsConfig.setStopTraceAfterUnexpected(true);
        tlsConfig.setQuickReceive(true);

        return tlsConfig;
    }
}
