/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

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
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.DtlsFeaturesResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class DtlsFeaturesProbe extends TlsProbe {

    public DtlsFeaturesProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.DTLS_FEATURES, configSelector);
    }

    @Override
    public ProbeResult executeTest() {
        return new DtlsFeaturesResult(supportsFragmentation(), supportsReordering());
    }

    private TestResult supportsFragmentation() {
        if (supportsFragmentationDirectly() == TestResult.TRUE) {
            return TestResult.TRUE;
        } else if (supportsFragmentationWithExtension() == TestResult.TRUE) {
            return TestResult.PARTIALLY;
        } else {
            return TestResult.FALSE;
        }
    }

    private TestResult supportsFragmentationDirectly() {
        Config config = getConfigSelector().getBaseConfig();
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        config.setDtlsMaximumFragmentLength(100);

        State state = new State(config);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, state.getWorkflowTrace())) {
            return TestResult.TRUE;
        } else {
            return TestResult.FALSE;
        }
    }

    private TestResult supportsFragmentationWithExtension() {
        Config config = getConfigSelector().getBaseConfig();
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
            return TestResult.TRUE;
        } else {
            return TestResult.FALSE;
        }
    }

    private TestResult supportsReordering() {
        Config config = getConfigSelector().getBaseConfig();
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
        return new DtlsFeaturesResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

}
