package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.RecordFragmentationResult;

public class RecordFragmentationProbe extends TlsProbe {
    public RecordFragmentationProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.RECORD_FRAGMENTATION, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        Config config = getScannerConfig().createConfig();
        config.setDefaultMaxRecordData(50);

        State state = new State(config, new WorkflowConfigurationFactory(config).createWorkflowTrace(WorkflowTraceType.HELLO, RunningModeType.CLIENT));

        executeState(state);

        return new RecordFragmentationResult(state.getWorkflowTrace().executedAsPlanned());
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return null;
    }

    @Override
    public void adjustConfig(SiteReport report) {

    }
}
