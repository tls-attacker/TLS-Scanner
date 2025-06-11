/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.PropertyTrueRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ExtensionRequirement;

public class RenegotiationProbe extends TlsClientProbe {

    private TestResult enforcesRenegotiationInfoFromServer = TestResults.COULD_NOT_TEST;

    public RenegotiationProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
        super(executor, TlsProbeType.RENEGOTIATION, scannerConfig);
        register(TlsAnalyzedProperty.ENFORCES_RENEGOTIATION_INFO_FROM_SERVER);
    }

    @Override
    protected void executeTest() {
        enforcesRenegotiationInfoFromServer = getEnforcesRenegotiationInfoFromServer();
    }

    private TestResult getEnforcesRenegotiationInfoFromServer() {
        Config config = scannerConfig.createConfig();
        config.setHighestProtocolVersion(ProtocolVersion.TLS12);
        config.setAddRenegotiationInfoExtension(false);
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(WorkflowTraceType.SHORT_HELLO, RunningModeType.SERVER);
        trace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = new State(config, trace);
        executeState(state);

        AlertMessage alertMessage =
                state.getWorkflowTrace().getLastReceivedMessage(AlertMessage.class);
        if (state.getWorkflowTrace().executedAsPlanned()
                && alertMessage != null
                && alertMessage.getLevel().equals(AlertLevel.FATAL)) {
            return TestResults.TRUE;
        }
        return TestResults.FALSE;
    }

    public static boolean socketClosed(SocketState socketState) {
        return (socketState == SocketState.SOCKET_EXCEPTION
                || socketState == SocketState.CLOSED
                || socketState == SocketState.IO_EXCEPTION);
    }

    public static boolean socketClosed(State state) {
        SocketState socketState = state.getTcpContext().getFinalSocketState();
        return socketClosed(socketState);
    }

    @Override
    public Requirement<ClientReport> getRequirements() {
        return new ProbeRequirement<ClientReport>(TlsProbeType.PROTOCOL_VERSION)
                .and(new PropertyTrueRequirement<>(TlsAnalyzedProperty.SUPPORTS_TLS_1_2))
                .and(new ExtensionRequirement<>(ExtensionType.RENEGOTIATION_INFO));
    }

    @Override
    public void adjustConfig(ClientReport report) {}

    @Override
    protected void mergeData(ClientReport report) {
        put(
                TlsAnalyzedProperty.ENFORCES_RENEGOTIATION_INFO_FROM_SERVER,
                enforcesRenegotiationInfoFromServer);
    }
}
