/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ActivateEncryptionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeWriteEpochAction;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;

public class DtlsBugsProbe extends TlsClientProbe {

    private TestResult isEarlyFinished = TestResults.COULD_NOT_TEST;
    private TestResult isAcceptingUnencryptedFinished = TestResults.COULD_NOT_TEST;

    public DtlsBugsProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
        super(executor, TlsProbeType.DTLS_COMMON_BUGS, scannerConfig);
        register(
                TlsAnalyzedProperty.ACCEPTS_UNENCRYPTED_FINISHED,
                TlsAnalyzedProperty.HAS_EARLY_FINISHED_BUG);
    }

    @Override
    protected void executeTest() {
        isAcceptingUnencryptedFinished = isAcceptingUnencryptedFinished();
        isEarlyFinished = isEarlyFinished();
    }

    private TestResult isAcceptingUnencryptedFinished() {
        Config config = scannerConfig.createConfig();
        config.setAddRetransmissionsToWorkflowTraceInDtls(true);

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.SERVER);
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
        trace.addTlsAction(new ChangeWriteEpochAction(0));
        trace.addTlsAction(new SendAction(new FinishedMessage()));
        GenericReceiveAction receiveAction = new GenericReceiveAction();
        trace.addTlsAction(receiveAction);

        State state = new State(config, trace);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()
                && receiveAction.getReceivedMessages().isEmpty()) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult isEarlyFinished() {
        Config config = scannerConfig.createConfig();
        config.setAddRetransmissionsToWorkflowTraceInDtls(true);

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.SERVER);
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
        trace.addTlsAction(new ActivateEncryptionAction());
        trace.addTlsAction(new SendAction(new FinishedMessage()));
        GenericReceiveAction receiveAction = new GenericReceiveAction();
        trace.addTlsAction(receiveAction);

        State state = new State(config, trace);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()
                && receiveAction.getReceivedMessages().isEmpty()) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    @Override
    public void adjustConfig(ClientReport report) {}

    @Override
    protected void mergeData(ClientReport report) {
        put(TlsAnalyzedProperty.ACCEPTS_UNENCRYPTED_FINISHED, isAcceptingUnencryptedFinished);
        put(TlsAnalyzedProperty.HAS_EARLY_FINISHED_BUG, isEarlyFinished);
    }

    @Override
    public Requirement<ClientReport> getRequirements() {
        return new ProtocolTypeTrueRequirement<>(ProtocolType.DTLS);
    }
}
