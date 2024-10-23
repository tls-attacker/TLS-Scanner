/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.quic;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.requirements.PropertyTrueRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.packet.InitialPacket;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeConnectionTimeoutAction;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TightReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.QuicAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.QuicProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.Arrays;

public class QuicRetryPacketProbe extends QuicServerProbe {

    public static Integer RETRY_TOKEN_LENGTH_ERROR_VALUE = -1;

    private TestResult hasRetryTokenRetransmissions;
    private TestResult checksRetryToken;
    private Integer retryTokenLength = RETRY_TOKEN_LENGTH_ERROR_VALUE;

    public QuicRetryPacketProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, QuicProbeType.RETRY_PACKET, configSelector);
        register(
                QuicAnalyzedProperty.HAS_RETRY_TOKEN_RETRANSMISSIONS,
                QuicAnalyzedProperty.HAS_RETRY_TOKEN_CHECKS,
                QuicAnalyzedProperty.RETRY_TOKEN_LENGTH);
    }

    @Override
    public void executeTest() {
        hasRetryTokenRetransmissions = hasRetryPacketRetransmissions();
        checksRetryToken = checksRetryToken();
    }

    private TestResult hasRetryPacketRetransmissions() {
        Config config = configSelector.getTls13BaseConfig();
        config.setExpectHandshakeDoneQuicFrame(false);

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new ChangeConnectionTimeoutAction(3000));
        trace.addTlsAction(new GenericReceiveAction());

        State state = new State(config, trace);
        executeState(state);

        int numberRetryPackets =
                WorkflowTraceResultUtil.getAllReceivedQuicPacketsOfType(
                                trace, QuicPacketType.RETRY_PACKET)
                        .size();
        if (numberRetryPackets > 1) {
            return TestResults.TRUE;
        } else if (numberRetryPackets == 1) {
            return TestResults.FALSE;
        } else {
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private TestResult checksRetryToken() {
        Config config = configSelector.getTls13BaseConfig();
        config.setExpectHandshakeDoneQuicFrame(false);
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);

        State state = new State(config);
        executeState(state);

        // Store length of the received token
        if (WorkflowTraceResultUtil.didReceiveQuicPacket(
                state.getWorkflowTrace(), QuicPacketType.RETRY_PACKET)) {
            retryTokenLength = state.getContext().getQuicContext().getInitialPacketToken().length;
            if (retryTokenLength == 0) {
                return TestResults.CANNOT_BE_TESTED;
            }
        } else {
            return TestResults.ERROR_DURING_TEST;
        }

        config = configSelector.getTls13BaseConfig();
        config.setExpectHandshakeDoneQuicFrame(false);

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        InitialPacket initialPacket = new InitialPacket();
        byte[] token = new byte[retryTokenLength];
        Arrays.fill(token, (byte) 255);
        initialPacket.setToken(Modifiable.xor(token, 0));
        SendAction sendAction = new SendAction(new ClientHelloMessage(config));
        sendAction.setConfiguredQuicPackets(initialPacket);
        trace.addTlsAction(sendAction);
        trace.addTlsAction(new TightReceiveAction(new ServerHelloMessage()));

        state = new State(config, trace);
        executeState(state);

        if (WorkflowTraceResultUtil.didReceiveQuicPacket(
                state.getWorkflowTrace(), QuicPacketType.RETRY_PACKET)) {
            if (WorkflowTraceResultUtil.didReceiveMessage(
                    state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO)) {
                return TestResults.FALSE;
            } else {
                return TestResults.TRUE;
            }
        } else {
            return TestResults.ERROR_DURING_TEST;
        }
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(QuicAnalyzedProperty.HAS_RETRY_TOKEN_RETRANSMISSIONS, hasRetryTokenRetransmissions);
        put(QuicAnalyzedProperty.HAS_RETRY_TOKEN_CHECKS, checksRetryToken);
        put(QuicAnalyzedProperty.RETRY_TOKEN_LENGTH, retryTokenLength);
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProtocolTypeTrueRequirement<ServerReport>(ProtocolType.QUIC)
                .and(new PropertyTrueRequirement<>(QuicAnalyzedProperty.RETRY_REQUIRED));
    }

    @Override
    public void adjustConfig(ServerReport report) {}
}
