/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeFalseRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.List;

public class RecordFragmentationProbe extends TlsServerProbe {

    private TestResult supportsFragmentation = TestResults.COULD_NOT_TEST;
    private int minRecordLength = 16384;

    public RecordFragmentationProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.RECORD_FRAGMENTATION, configSelector);
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
        Config config = configSelector.getAnyWorkingBaseConfig();
        config.setDefaultMaxRecordData(recordLength);
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        State state = new State(config);
        executeState(state);
        HandshakeMessageType expectedFinalMessage =
                state.getTlsContext().getSelectedProtocolVersion() == ProtocolVersion.TLS13
                        ? HandshakeMessageType.FINISHED
                        : HandshakeMessageType.SERVER_HELLO_DONE;
        return WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), expectedFinalMessage);
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProtocolTypeFalseRequirement<>(ProtocolType.DTLS);
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION, supportsFragmentation);
        put(TlsAnalyzedProperty.MIN_RECORD_LENGTH, minRecordLength);
    }
}
