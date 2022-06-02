/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;

public class ClientRecordFragmentationProbe extends TlsClientProbe<ClientScannerConfig, ClientReport> {

    private TestResult result;

    public ClientRecordFragmentationProbe(ClientScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.RECORD_FRAGMENTATION, scannerConfig);
        register(TlsAnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION);
    }

    @Override
    public void executeTest() {
        Config config = scannerConfig.createConfig();
        config.setDefaultMaxRecordData(50);

        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace workflowTrace = factory.createWorkflowTrace(WorkflowTraceType.HELLO, RunningModeType.SERVER);
        workflowTrace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
        State state = new State(config, workflowTrace);

        executeState(state);

        result = state.getWorkflowTrace().executedAsPlanned() ? TestResults.TRUE : TestResults.FALSE;
    }

    @Override
    public void adjustConfig(ClientReport report) {

    }

    @Override
    protected void mergeData(ClientReport report) {
        put(TlsAnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION, result);
    }

    @Override
    protected Requirement getRequirements() {
        return Requirement.NO_REQUIREMENT;
    }

}
