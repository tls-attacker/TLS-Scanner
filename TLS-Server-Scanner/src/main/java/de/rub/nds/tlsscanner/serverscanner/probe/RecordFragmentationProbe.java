/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

<<<<<<< HEAD
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
=======
import de.rub.nds.scanner.core.constants.TestResults;
>>>>>>> master
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
<<<<<<< HEAD
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class RecordFragmentationProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private TestResult supported;
=======
import de.rub.nds.tlsscanner.core.probe.result.RecordFragmentationResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class RecordFragmentationProbe
        extends TlsServerProbe<
                ConfigSelector, ServerReport, RecordFragmentationResult<ServerReport>> {
>>>>>>> master

    public RecordFragmentationProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.RECORD_FRAGMENTATION, configSelector);
        register(TlsAnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION);
    }

    @Override
<<<<<<< HEAD
    public void executeTest() {
        Config config = configSelector.getBaseConfig();
=======
    public RecordFragmentationResult executeTest() {
        Config config = configSelector.getAnyWorkingBaseConfig();
>>>>>>> master
        config.setDefaultMaxRecordData(50);
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        State state = new State(config);
        executeState(state);
<<<<<<< HEAD
        supported =
            WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, state.getWorkflowTrace())
                ? TestResults.TRUE : TestResults.FALSE;
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

    @Override
    protected Requirement getRequirements() {
        return Requirement.NO_REQUIREMENT;
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION, supported);
    }
=======
        HandshakeMessageType expectedFinalMessage = HandshakeMessageType.SERVER_HELLO_DONE;
        if (state.getTlsContext().getSelectedProtocolVersion() == ProtocolVersion.TLS13) {
            expectedFinalMessage = HandshakeMessageType.FINISHED;
        }
        if (WorkflowTraceUtil.didReceiveMessage(expectedFinalMessage, state.getWorkflowTrace())) {
            return new RecordFragmentationResult(TestResults.TRUE);
        } else {
            return new RecordFragmentationResult(TestResults.FALSE);
        }
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return true;
    }

    @Override
    public RecordFragmentationResult getCouldNotExecuteResult() {
        return new RecordFragmentationResult(null);
    }

    @Override
    public void adjustConfig(ServerReport report) {}
>>>>>>> master
}
