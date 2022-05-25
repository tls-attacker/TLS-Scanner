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
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.DtlsBugsResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class DtlsBugsProbe extends TlsServerProbe<ConfigSelector, ServerReport, DtlsBugsResult> {

    public DtlsBugsProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.DTLS_COMMON_BUGS, configSelector);
    }

    @Override
    public DtlsBugsResult executeTest() {
        try {
            return new DtlsBugsResult(isAcceptingUnencryptedFinished(), isAcceptingUnencryptedAppData(),
                isEarlyFinished());
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new DtlsBugsResult(TestResults.ERROR_DURING_TEST, TestResults.ERROR_DURING_TEST,
                TestResults.ERROR_DURING_TEST);
        }
    }

    private TestResult isAcceptingUnencryptedFinished() {
        Config config = configSelector.getBaseConfig();
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
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult isAcceptingUnencryptedAppData() {
        Config config = configSelector.getBaseConfig();
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
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult isEarlyFinished() {
        Config config = configSelector.getBaseConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(config)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(new FinishedMessage(config)));
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage(config)));
        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return true;
    }

    @Override
    public DtlsBugsResult getCouldNotExecuteResult() {
        return new DtlsBugsResult(TestResults.COULD_NOT_TEST, TestResults.COULD_NOT_TEST, TestResults.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

}
