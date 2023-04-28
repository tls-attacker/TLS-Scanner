/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.http.HttpRequestMessage;
import de.rub.nds.tlsattacker.core.layer.constant.LayerConfiguration;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

import java.io.IOException;

/**
 * Determines when the server closes the connection. It's meant for tests in the lab so we limit the
 * probe. Note that NO_RESULT may indicate that we couldn't identify a closing delta, i.e the server
 * didn't close the connection within our limit or the probe could not be executed.
 */
public class ConnectionClosingProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    public static final long NO_RESULT = -1;
    private static final long LIMIT = 5000;

    private boolean useHttpAppData = false;
    private long closedAfterFinishedDelta = NO_RESULT;
    private long closedAfterAppDataDelta = NO_RESULT;

    public ConnectionClosingProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.CONNECTION_CLOSING_DELTA, configSelector);
    }

    @Override
    public void executeTest() {
        Config tlsConfig = configSelector.getAnyWorkingBaseConfig();
        configSelector.repairConfig(tlsConfig);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.HTTPS);
        tlsConfig.setWorkflowExecutorShouldClose(false);

        WorkflowTrace handshakeOnly = getWorkflowTrace(tlsConfig);
        WorkflowTrace handshakeWithAppData = getWorkflowTrace(tlsConfig);
        if (useHttpAppData) {
            tlsConfig.setDefaultLayerConfiguration(LayerConfiguration.HTTPS);
            handshakeWithAppData.addTlsAction(new SendAction(new HttpRequestMessage()));
        } else {
            handshakeWithAppData.addTlsAction(new SendAction(new ApplicationMessage()));
        }
        closedAfterFinishedDelta = evaluateClosingDelta(tlsConfig, handshakeOnly);
        closedAfterAppDataDelta = evaluateClosingDelta(tlsConfig, handshakeWithAppData);
    }

    public WorkflowTrace getWorkflowTrace(Config tlsConfig) {
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(tlsConfig);
        return factory.createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.CLIENT);
    }

    private long evaluateClosingDelta(Config tlsConfig, WorkflowTrace workflowTrace) {
        State state = new State(tlsConfig, workflowTrace);
        executeState(state);
        long delta = 0;
        SocketState socketState = null;
        do {
            try {
                socketState =
                        (((TcpTransportHandler) (state.getTlsContext().getTransportHandler()))
                                .getSocketState());
                switch (socketState) {
                    case CLOSED:
                    case IO_EXCEPTION:
                    case PEER_WRITE_CLOSED:
                    case SOCKET_EXCEPTION:
                    case TIMEOUT:
                        closeSocket(state);
                        return delta;
                    default:
                }
                Thread.sleep(10);
                delta += 10;
            } catch (InterruptedException ignored) {
            }
        } while (delta < LIMIT);
        closeSocket(state);
        return NO_RESULT;
    }

    public void closeSocket(State state) {
        try {
            state.getTlsContext().getTransportHandler().closeConnection();
        } catch (IOException ignored) {
        }
    }

    @Override
    public void adjustConfig(ServerReport report) {
        useHttpAppData = report.getResult(TlsAnalyzedProperty.SUPPORTS_HTTPS) == TestResults.TRUE;
    }

    @Override
    protected void mergeData(ServerReport report) {
        report.setClosedAfterAppDataDelta(closedAfterAppDataDelta);
        report.setClosedAfterFinishedDelta(closedAfterFinishedDelta);
    }

    @Override
    protected Requirement getRequirements() {
        return new ProbeRequirement(TlsProbeType.HTTP_HEADER);
    }
}
