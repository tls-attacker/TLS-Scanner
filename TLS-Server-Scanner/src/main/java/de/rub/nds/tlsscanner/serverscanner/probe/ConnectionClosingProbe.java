/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
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
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.probe.result.ConnectionClosingResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * Determines when the server closes the connection. It's meant for tests in the lab so we limit the probe.
 */
public class ConnectionClosingProbe extends TlsServerProbe<ConfigSelector, ServerReport, ConnectionClosingResult> {

    public static final long NO_RESULT = -1;
    private static final long LIMIT = 5000;

    private boolean useHttpAppData = false;

    public ConnectionClosingProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.CONNECTION_CLOSING_DELTA, configSelector);
    }

    @Override
    public ConnectionClosingResult executeTest() {
        Config tlsConfig = configSelector.getBaseConfig();
        configSelector.repairConfig(tlsConfig);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.HTTPS);
        tlsConfig.setWorkflowExecutorShouldClose(false);

        WorkflowTrace handshakeOnly = getWorkflowTrace(tlsConfig);
        WorkflowTrace handshakeWithAppData = getWorkflowTrace(tlsConfig);
        if (useHttpAppData) {
            handshakeWithAppData.addTlsAction(new SendAction(new HttpsRequestMessage(tlsConfig)));
        } else {
            handshakeWithAppData.addTlsAction(new SendAction(new ApplicationMessage(tlsConfig)));
        }

        return new ConnectionClosingResult(evaluateClosingDelta(tlsConfig, handshakeOnly),
            evaluateClosingDelta(tlsConfig, handshakeWithAppData));
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
                socketState = (((TcpTransportHandler) (state.getTlsContext().getTransportHandler())).getSocketState());
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
    public boolean canBeExecuted(ServerReport report) {
        return report.isProbeAlreadyExecuted(TlsProbeType.HTTP_HEADER);
    }

    @Override
    public ConnectionClosingResult getCouldNotExecuteResult() {
        return new ConnectionClosingResult(NO_RESULT, NO_RESULT);
    }

    @Override
    public void adjustConfig(ServerReport report) {
        useHttpAppData = report.getResult(TlsAnalyzedProperty.SUPPORTS_HTTPS) == TestResults.TRUE;
    }

}
