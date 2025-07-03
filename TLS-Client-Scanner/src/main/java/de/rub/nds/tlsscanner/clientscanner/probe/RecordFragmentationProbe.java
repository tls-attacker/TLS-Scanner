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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeFalseRequirement;
import java.util.List;

public class RecordFragmentationProbe extends TlsClientProbe {

    private TestResult supportsFragmentation = TestResults.COULD_NOT_TEST;
    private int minRecordLength = 16384;

    public RecordFragmentationProbe(
            ParallelExecutor parallelExecutor, ClientScannerConfig scannerConfig) {
        super(parallelExecutor, TlsProbeType.RECORD_FRAGMENTATION, scannerConfig);
        register(TlsAnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION);
        register(TlsAnalyzedProperty.MIN_RECORD_LENGTH);
    }

    @Override
    protected void executeTest() {
        List<Integer> toTest = List.of(16384, 111, 50, 1);
        for (Integer length : toTest) {
            if (supportsFragmentation(length)) {
                minRecordLength = length;
            } else {
                break;
            }
        }

        supportsFragmentation = minRecordLength < 16384 ? TestResults.TRUE : TestResults.FALSE;
    }

    public boolean supportsFragmentation(int recordLength) {
        Config config = scannerConfig.createConfig();
        config.setDefaultMaxRecordData(recordLength);

        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace workflowTrace =
                factory.createWorkflowTrace(WorkflowTraceType.HELLO, RunningModeType.SERVER);
        workflowTrace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

        State state = new State(config, workflowTrace);
        executeState(state);

        return WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.FINISHED);
    }

    @Override
    public Requirement<ClientReport> getRequirements() {
        return new ProtocolTypeFalseRequirement<ClientReport>(ProtocolType.DTLS);
    }

    @Override
    public void adjustConfig(ClientReport report) {}

    @Override
    protected void mergeData(ClientReport report) {
        put(TlsAnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION, supportsFragmentation);
        put(TlsAnalyzedProperty.MIN_RECORD_LENGTH, minRecordLength);
    }
}
