/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ActivateEncryptionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeWriteEpochAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.DtlsFeaturesResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class DtlsFeaturesProbe extends TlsServerProbe<ConfigSelector, ServerReport, DtlsFeaturesResult> {

    public DtlsFeaturesProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.DTLS_FEATURES, configSelector);
    }

    @Override
    public DtlsFeaturesResult executeTest() {
        return new DtlsFeaturesResult(supportsFragmentation(), supportsReordering());
    }

    private TestResult supportsFragmentation() {
        if (supportsFragmentationDirectly() == TestResults.TRUE) {
            return TestResults.TRUE;
        } else if (supportsFragmentationWithExtension() == TestResults.TRUE) {
            return TestResults.PARTIALLY;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult supportsFragmentationDirectly() {
        Config config = configSelector.getBaseConfig();
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        config.setDtlsMaximumFragmentLength(100);

        State state = new State(config);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, state.getWorkflowTrace())) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult supportsFragmentationWithExtension() {
        Config config = configSelector.getBaseConfig();
        config.setAddMaxFragmentLengthExtension(Boolean.TRUE);
        config.setDefaultMaxFragmentLength(MaxFragmentLength.TWO_11);
        WorkflowTrace trace = new WorkflowConfigurationFactory(config)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        SendDynamicClientKeyExchangeAction action = new SendDynamicClientKeyExchangeAction();
        action.setFragments(new DtlsHandshakeMessageFragment(config, 20), new DtlsHandshakeMessageFragment(config, 20));
        trace.addTlsAction(action);
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(config), new FinishedMessage(config)));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage(config)));

        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult supportsReordering() {
        Config config = configSelector.getBaseConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(config)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new ActivateEncryptionAction());
        trace.addTlsAction(new SendAction(new FinishedMessage(config)));
        trace.addTlsAction(new ChangeWriteEpochAction(0));
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(config)));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage(config)));

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
    public DtlsFeaturesResult getCouldNotExecuteResult() {
        return new DtlsFeaturesResult(TestResults.COULD_NOT_TEST, TestResults.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

}
