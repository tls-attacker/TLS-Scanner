/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
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
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class HeartbleedProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private TestResult vulnerable;

    public HeartbleedProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.HEARTBLEED, configSelector);
        super.register(TlsAnalyzedProperty.VULNERABLE_TO_HEARTBLEED);
    }

    @Override
    public void executeTest() {
        Config tlsConfig = configSelector.getBaseConfig();
        tlsConfig.setAddHeartbeatExtension(true);

        State state = new State(tlsConfig, getTrace(tlsConfig));
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.HEARTBEAT, state.getWorkflowTrace()))
            vulnerable = TestResults.TRUE;
        else if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace()))
            vulnerable = TestResults.UNCERTAIN;
        else
            vulnerable = TestResults.FALSE;
    }

    private WorkflowTrace getTrace(Config tlsConfig) {
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);
        HeartbeatMessage heartbeatMessage = new HeartbeatMessage(tlsConfig);
        heartbeatMessage.setPayload(Modifiable.explicit(new byte[] { 1, 3 }));
        heartbeatMessage.setPayloadLength(Modifiable.explicit(20000));
        trace.addTlsAction(new SendAction(heartbeatMessage));
        trace.addTlsAction(new ReceiveAction(new HeartbeatMessage()));
        return trace;
    }

    @Override
    public void adjustConfig(ServerReport report) {

    }

    @Override
    protected Requirement getRequirements() {
        return new ProbeRequirement().requireProbeTypes(TlsProbeType.EXTENSIONS)
            .requireExtensionTyes(ExtensionType.HEARTBEAT);
    }

    @Override
    protected void mergeData(ServerReport report) {
        super.put(TlsAnalyzedProperty.VULNERABLE_TO_HEARTBLEED, vulnerable);
    }
}
