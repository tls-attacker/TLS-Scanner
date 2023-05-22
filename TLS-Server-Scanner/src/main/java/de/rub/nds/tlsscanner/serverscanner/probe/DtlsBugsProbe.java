/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class DtlsBugsProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private TestResult isEarlyFinished = TestResults.COULD_NOT_TEST;
    private TestResult isAcceptingUnencryptedFinished = TestResults.COULD_NOT_TEST;

    public DtlsBugsProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.DTLS_COMMON_BUGS, configSelector);
        register(
                TlsAnalyzedProperty.ACCEPTS_UNENCRYPTED_FINISHED,
                TlsAnalyzedProperty.HAS_EARLY_FINISHED_BUG);
    }

    @Override
    public void executeTest() {
        isEarlyFinished = isAcceptingUnencryptedFinished();
        isAcceptingUnencryptedFinished = isEarlyFinished();
    }

    private TestResult isAcceptingUnencryptedFinished() {
        Config config = configSelector.getBaseConfig();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
        SendAction sendAction = new SendAction(new FinishedMessage());
        Record record = new Record(config);
        record.setEpoch(Modifiable.explicit(0));
        sendAction.setRecords(record);
        trace.addTlsAction(sendAction);
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(
                HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult isEarlyFinished() {
        Config config = configSelector.getBaseConfig();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(new FinishedMessage()));
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(
                HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    @Override
    public Requirement getRequirements() {
        return Requirement.NO_REQUIREMENT;
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.ACCEPTS_UNENCRYPTED_FINISHED, isAcceptingUnencryptedFinished);
        put(TlsAnalyzedProperty.HAS_EARLY_FINISHED_BUG, isEarlyFinished);
    }
}
