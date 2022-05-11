/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.integer.IntegerModificationFactory;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.HeartbleedResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class HeartbleedProbe extends TlsServerProbe<ConfigSelector, ServerReport, HeartbleedResult> {

    public HeartbleedProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.HEARTBLEED, configSelector);
    }

    @Override
    public HeartbleedResult executeTest() {
        return new HeartbleedResult(isVulnerable());
    }

    private TestResults isVulnerable() {
        Config tlsConfig = configSelector.getBaseConfig();
        tlsConfig.setAddHeartbeatExtension(true);

        State state = new State(tlsConfig, getTrace(tlsConfig));
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.HEARTBEAT, state.getWorkflowTrace())) {
            return TestResults.TRUE;
        } else if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            return TestResults.UNCERTAIN;
        } else {
            return TestResults.FALSE;
        }
    }

    private WorkflowTrace getTrace(Config tlsConfig) {
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);
        trace.addTlsAction(new SendAction(getMalformedHeartbeatMessage()));
        trace.addTlsAction(new ReceiveAction(new HeartbeatMessage()));
        return trace;
    }

    private HeartbeatMessage getMalformedHeartbeatMessage() {
        HeartbeatMessage message = new HeartbeatMessage();
        message.getPayload().setModification(ByteArrayModificationFactory.explicitValue(new byte[] { 1, 3 }));
        message.getPayloadLength().setModification(IntegerModificationFactory.explicitValue(20000));
        return message;
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return report.isProbeAlreadyExecuted(TlsProbeType.EXTENSIONS) && !report.getSupportedExtensions().isEmpty();
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

    @Override
    public HeartbleedResult getCouldNotExecuteResult() {
        return new HeartbleedResult(TestResults.COULD_NOT_TEST);
    }
}
