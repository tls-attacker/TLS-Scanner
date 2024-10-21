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
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.QuicAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.QuicProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.List;

public class QuicAfterHandshakeProbe extends QuicServerProbe {

    private TestResults isNewTokenFrameSend;
    private Integer numberOfNewTokenFrames;
    private Long tokenLength;
    private TestResults isNewConnectionIdFramesSend;
    private Integer numberOfNewConnectionIdsFrames;

    public QuicAfterHandshakeProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, QuicProbeType.AFTER_HANDSHAKE, configSelector);
        register(
                QuicAnalyzedProperty.IS_NEW_TOKEN_FRAME_SEND,
                QuicAnalyzedProperty.NUMBER_OF_NEW_TOKEN_FRAMES,
                QuicAnalyzedProperty.NEW_TOKEN_LENGTH,
                QuicAnalyzedProperty.IS_NEW_CONNECTION_ID_FRAME_SEND,
                QuicAnalyzedProperty.NUMBER_OF_NEW_CONNECTION_ID_FRAMES);
    }

    @Override
    public void executeTest() {
        Config config = configSelector.getTls13BaseConfig();
        config.setExpectHandshakeDoneQuicFrame(true);

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createDynamicHandshakeWorkflow(config.getDefaultClientConnection());
        trace.addTlsAction(new GenericReceiveAction());

        State state = new State(config, trace);
        executeState(state);

        if (state.getWorkflowTrace().executedAsPlanned()) {
            // NEW TOKEN analysis
            if (WorkflowTraceResultUtil.didReceiveQuicFrame(
                    state.getWorkflowTrace(), QuicFrameType.NEW_TOKEN_FRAME)) {
                List<QuicFrame> newTokens =
                        WorkflowTraceResultUtil.getAllReceivedQuicFramesOfType(
                                state.getWorkflowTrace(), QuicFrameType.NEW_TOKEN_FRAME);
                if (newTokens.size() > 0) {
                    isNewTokenFrameSend = TestResults.TRUE;
                    numberOfNewTokenFrames = newTokens.size();
                    tokenLength = ((NewTokenFrame) newTokens.get(0)).getTokenLength().getValue();
                }
            } else {
                isNewTokenFrameSend = TestResults.FALSE;
            }
            // NEW CONNECTION ID analysis
            if (WorkflowTraceResultUtil.didReceiveQuicFrame(
                    state.getWorkflowTrace(), QuicFrameType.NEW_CONNECTION_ID_FRAME)) {
                List<QuicFrame> newConnectionIds =
                        WorkflowTraceResultUtil.getAllReceivedQuicFramesOfType(
                                state.getWorkflowTrace(), QuicFrameType.NEW_CONNECTION_ID_FRAME);
                if (newConnectionIds.size() > 0) {
                    isNewConnectionIdFramesSend = TestResults.TRUE;
                    numberOfNewConnectionIdsFrames = newConnectionIds.size();
                }
            } else {
                isNewConnectionIdFramesSend = TestResults.FALSE;
            }
        } else {
            isNewTokenFrameSend = TestResults.ERROR_DURING_TEST;
            isNewConnectionIdFramesSend = TestResults.ERROR_DURING_TEST;
        }
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(QuicAnalyzedProperty.IS_NEW_TOKEN_FRAME_SEND, isNewTokenFrameSend);
        put(QuicAnalyzedProperty.NUMBER_OF_NEW_TOKEN_FRAMES, numberOfNewTokenFrames);
        put(QuicAnalyzedProperty.NEW_TOKEN_LENGTH, tokenLength);
        put(QuicAnalyzedProperty.IS_NEW_CONNECTION_ID_FRAME_SEND, isNewConnectionIdFramesSend);
        put(
                QuicAnalyzedProperty.NUMBER_OF_NEW_CONNECTION_ID_FRAMES,
                numberOfNewConnectionIdsFrames);
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProtocolTypeTrueRequirement<>(ProtocolType.QUIC);
    }

    @Override
    public void adjustConfig(ServerReport report) {}
}
