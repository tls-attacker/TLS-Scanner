/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.FulfilledRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;

public class ApplicationMessageProbe extends TlsClientProbe {

    private TestResult sendsApplicationMessage = TestResults.COULD_NOT_TEST;

    public ApplicationMessageProbe(
            ParallelExecutor parallelExecutor, ClientScannerConfig scannerConfig) {
        super(parallelExecutor, TlsProbeType.APPLICATION_MESSAGE, scannerConfig);
        register(TlsAnalyzedProperty.SENDS_APPLICATION_MESSAGE);
    }

    @Override
    protected void executeTest() {
        Config config = scannerConfig.createConfig();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER);
        trace.addTlsAction(new ReceiveAction(new ApplicationMessage()));

        State state = new State(config, trace);
        executeState(state);
        sendsApplicationMessage =
                state.getWorkflowTrace().executedAsPlanned() ? TestResults.TRUE : TestResults.FALSE;
    }

    @Override
    public void adjustConfig(ClientReport report) {}

    @Override
    protected void mergeData(ClientReport report) {
        put(TlsAnalyzedProperty.SENDS_APPLICATION_MESSAGE, sendsApplicationMessage);
    }

    @Override
    public Requirement<ClientReport> getRequirements() {
        return new FulfilledRequirement<>();
    }
}
