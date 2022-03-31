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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.DtlsBugsResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class DtlsBugsProbe extends TlsProbe {

    public DtlsBugsProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.DTLS_COMMON_BUGS, configSelector);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            return new DtlsBugsResult(isAcceptingUnencryptedFinished(), isAcceptingUnencryptedAppData(),
                isEarlyFinished());
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new DtlsBugsResult(TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST,
                TestResult.ERROR_DURING_TEST);
        }
    }

    private TestResult isAcceptingUnencryptedFinished() {
        Config config = getConfigSelector().getBaseConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(config)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(config)));
        SendAction sendAction = new SendAction(new FinishedMessage(config));
        Record record = new Record(config);
        record.setEpoch(Modifiable.explicit(0));
        sendAction.setRecords(record);
        trace.addTlsAction(sendAction);
        trace.addTlsAction(new GenericReceiveAction());
        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            return TestResult.TRUE;
        } else {
            return TestResult.FALSE;
        }
    }

    private TestResult isAcceptingUnencryptedAppData() {
        Config config = getConfigSelector().getBaseConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(config)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);
        trace.addTlsAction(new SendAction(new ApplicationMessage(config)));
        trace.addTlsAction(new GenericReceiveAction());
        State state = new State(config, trace);
        executeState(state);
        ProtocolMessage receivedMessage = WorkflowTraceUtil.getLastReceivedMessage(state.getWorkflowTrace());

        trace = new WorkflowConfigurationFactory(config).createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE,
            RunningModeType.CLIENT);
        SendAction sendAction = new SendAction(new ApplicationMessage(config));
        Record record = new Record(config);
        record.setEpoch(Modifiable.explicit(0));
        sendAction.setRecords(record);
        trace.addTlsAction(sendAction);
        trace.addTlsAction(new GenericReceiveAction());
        state = new State(config, trace);
        executeState(state);
        ProtocolMessage receivedMessageModified = WorkflowTraceUtil.getLastReceivedMessage(state.getWorkflowTrace());
        if (receivedMessage != null && receivedMessageModified != null && receivedMessage.getCompleteResultingMessage()
            .equals(receivedMessageModified.getCompleteResultingMessage())) {
            return TestResult.TRUE;
        } else {
            return TestResult.FALSE;
        }
    }

    private TestResult isEarlyFinished() {
        Config config = getConfigSelector().getBaseConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(config)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(new FinishedMessage(config)));
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage(config)));
        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            return TestResult.TRUE;
        } else {
            return TestResult.FALSE;
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new DtlsBugsResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

}
