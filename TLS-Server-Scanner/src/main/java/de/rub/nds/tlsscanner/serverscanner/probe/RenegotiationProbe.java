/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
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
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 *
 * @author robert
 */
public class RenegotiationProbe extends TlsProbe {

    private Set<CipherSuite> supportedSuites;
    private TestResult supportsRenegotiationExtension;

    public RenegotiationProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.RENEGOTIATION, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            TestResult supportsSecureRenegotiation;
            if (supportsRenegotiationExtension == TestResult.TRUE) {
                supportsSecureRenegotiation = supportsSecureClientRenegotiation();
            } else {
                supportsSecureRenegotiation = TestResult.FALSE;
            }
            TestResult supportsInsecureRenegotiation = supportsInsecureClientRenegotiation();
            return new RenegotiationResult(supportsSecureRenegotiation, supportsInsecureRenegotiation);
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new RenegotiationResult(TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST);
        }
    }

    private TestResult supportsSecureClientRenegotiation() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        List<CipherSuite> ciphersuites = new LinkedList<>();
        ciphersuites.addAll(supportedSuites);
        // TODO this can fail in some rare occasions
        tlsConfig.setDefaultClientSupportedCipherSuites(ciphersuites.get(0));
        tlsConfig.setDefaultSelectedCipherSuite(tlsConfig.getDefaultClientSupportedCipherSuites().get(0));
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.CLIENT_RENEGOTIATION_WITHOUT_RESUMPTION);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(true);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setDefaultClientNamedGroups(NamedGroup.getImplemented());
        tlsConfig.getDefaultClientNamedGroups().remove(NamedGroup.ECDH_X25519);
        WorkflowConfigurationFactory configFactory = new WorkflowConfigurationFactory(tlsConfig);
        WorkflowTrace trace = configFactory.createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE,
                RunningModeType.CLIENT);
        trace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(tlsConfig)));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        State state = new State(tlsConfig, trace);
        executeState(state);
        return state.getWorkflowTrace().executedAsPlanned() == true ? TestResult.TRUE : TestResult.FALSE;
    }

    private TestResult supportsInsecureClientRenegotiation() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        List<CipherSuite> ciphersuites = new LinkedList<>();
        ciphersuites.addAll(supportedSuites);
        tlsConfig.setDefaultClientSupportedCipherSuites(ciphersuites);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HANDSHAKE);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setAddRenegotiationInfoExtension(false);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setDefaultClientNamedGroups(NamedGroup.getImplemented());
        tlsConfig.getDefaultClientNamedGroups().remove(NamedGroup.ECDH_X25519);
        WorkflowConfigurationFactory configFactory = new WorkflowConfigurationFactory(tlsConfig);
        WorkflowTrace trace = configFactory.createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE,
                RunningModeType.CLIENT);
        trace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(tlsConfig)));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        State state = new State(tlsConfig, trace);
        executeState(state);
        return state.getWorkflowTrace().executedAsPlanned() == true ? TestResult.TRUE : TestResult.FALSE;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return (report.getCipherSuites() != null && (report.getCipherSuites().size() > 0 || supportsOnlyTls13(report)) && report
                .getResult(AnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION) != TestResult.NOT_TESTED_YET);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        supportedSuites = report.getCipherSuites();
        supportsRenegotiationExtension = report.getResult(AnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION);
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new RenegotiationResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST);
    }

    /**
     * Used to run the probe with empty CS list if we already know versions
     * before TLS 1.3 are not supported, to avoid stalling of probes that depend
     * on this one
     */
    private boolean supportsOnlyTls13(SiteReport report) {
        return report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0) == TestResult.FALSE
                && report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1) == TestResult.FALSE
                && report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2) == TestResult.FALSE;
    }
}
