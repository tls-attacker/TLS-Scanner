/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.quic;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.frame.NewTokenFrame;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.QuicAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.QuicProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.List;

public class QuicAfterHandshakeProbe extends QuicServerProbe {

    private TestResults isNewTokenSend = TestResults.FALSE;
    private Integer numberOfNewTokens;
    private Long newTokenLength;
    private TestResults isNewConnectionIdSend = TestResults.FALSE;
    private Integer numberOfNewConnectionIds;

    public QuicAfterHandshakeProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, QuicProbeType.AFTER_HANDSHAKE, configSelector);
        register(
                QuicAnalyzedProperty.IS_NEW_TOKEN_FRAME_SEND,
                QuicAnalyzedProperty.NUMBER_OF_NEW_TOKENS,
                QuicAnalyzedProperty.NEW_TOKEN_LENGTH,
                QuicAnalyzedProperty.IS_NEW_CONNECTION_ID_FRAME_SEND,
                QuicAnalyzedProperty.NUMBER_OF_NEW_CONNECTION_IDS);
    }

    @Override
    public void executeTest() {
        Config config = configSelector.getTls13BaseConfig();
        config.setExpectHandshakeDoneQuicFrame(true);
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HANDSHAKE);

        State state = new State(config);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            List<QuicFrame> frames =
                    WorkflowTraceResultUtil.getAllReceivedQuicFrames(state.getWorkflowTrace());
            if (WorkflowTraceResultUtil.didReceiveQuicFrame(
                    state.getWorkflowTrace(), QuicFrameType.NEW_TOKEN_FRAME)) {
                List<QuicFrame> newTokens =
                        WorkflowTraceResultUtil.getAllReceivedQuicFramesOfType(
                                state.getWorkflowTrace(), QuicFrameType.NEW_TOKEN_FRAME);
                if (newTokens.size() > 0) {
                    isNewTokenSend = TestResults.TRUE;
                    numberOfNewTokens = newTokens.size();
                    newTokenLength = ((NewTokenFrame) newTokens.get(0)).getTokenLength().getValue();
                }
            }
            if (WorkflowTraceResultUtil.didReceiveQuicFrame(
                    state.getWorkflowTrace(), QuicFrameType.NEW_CONNECTION_ID_FRAME)) {
                List<QuicFrame> newConnectionIds =
                        WorkflowTraceResultUtil.getAllReceivedQuicFramesOfType(
                                state.getWorkflowTrace(), QuicFrameType.NEW_CONNECTION_ID_FRAME);
                if (newConnectionIds.size() > 0) {
                    isNewConnectionIdSend = TestResults.TRUE;
                    numberOfNewConnectionIds = newConnectionIds.size();
                }
            }
        }
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(QuicAnalyzedProperty.IS_NEW_TOKEN_FRAME_SEND, isNewTokenSend);
        put(QuicAnalyzedProperty.NUMBER_OF_NEW_TOKENS, numberOfNewTokens);
        put(QuicAnalyzedProperty.NEW_TOKEN_LENGTH, newTokenLength);
        put(QuicAnalyzedProperty.IS_NEW_CONNECTION_ID_FRAME_SEND, isNewConnectionIdSend);
        put(QuicAnalyzedProperty.NUMBER_OF_NEW_CONNECTION_IDS, numberOfNewConnectionIds);
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProtocolTypeTrueRequirement<>(ProtocolType.QUIC);
    }

    @Override
    public void adjustConfig(ServerReport report) {}
}
