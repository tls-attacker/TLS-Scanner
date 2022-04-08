/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.probe.result.RecordFragmentationResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.requirements.ProbeRequirement;

public class RecordFragmentationProbe extends TlsProbe<ServerScannerConfig, ServerReport, RecordFragmentationResult> {

    public RecordFragmentationProbe(ServerScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.RECORD_FRAGMENTATION, scannerConfig);
    }

    @Override
    public RecordFragmentationResult executeTest() {
        Config config = getScannerConfig().createConfig();
        config.setDefaultMaxRecordData(50);

        State state = new State(config, new WorkflowConfigurationFactory(config)
            .createWorkflowTrace(WorkflowTraceType.HELLO, RunningModeType.CLIENT));

        executeState(state);

        return new RecordFragmentationResult(
            WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, state.getWorkflowTrace()));
    }

    @Override
    public RecordFragmentationResult getCouldNotExecuteResult() {
        return new RecordFragmentationResult(null);
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

	@Override
	protected Requirement getRequirements(ServerReport report) {
		return new ProbeRequirement(report);
	}
}
