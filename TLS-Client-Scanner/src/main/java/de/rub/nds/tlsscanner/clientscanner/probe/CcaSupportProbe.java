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
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;

public class CcaSupportProbe extends TlsClientProbe {

    private TestResult supportsCca = TestResults.COULD_NOT_TEST;

    public CcaSupportProbe(ParallelExecutor parallelExecutor, ClientScannerConfig scannerConfig) {
        super(parallelExecutor, TlsProbeType.CCA_SUPPORT, scannerConfig);
        register(TlsAnalyzedProperty.SUPPORTS_CCA);
    }

    @Override
    protected void executeTest() {
        Config config = scannerConfig.createConfig();
        config.setClientAuthentication(true);

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(WorkflowTraceType.HELLO, RunningModeType.SERVER);
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

        State state = new State(config, trace);
        executeState(state);
        supportsCca =
                WorkflowTraceResultUtil.didReceiveMessage(
                                state.getWorkflowTrace(), HandshakeMessageType.CERTIFICATE)
                        ? TestResults.TRUE
                        : TestResults.FALSE;
    }

    @Override
    public void adjustConfig(ClientReport report) {}

    @Override
    protected void mergeData(ClientReport report) {
        put(TlsAnalyzedProperty.SUPPORTS_CCA, supportsCca);
    }

    @Override
    public Requirement<ClientReport> getRequirements() {
        return new FulfilledRequirement<>();
    }
}
