/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.quic;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.quic.frame.CryptoFrame;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.QuicAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.QuicProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class QuicFragmentationProbe extends QuicServerProbe {

    private TestResult processesSplittedClientHello = TestResults.COULD_NOT_TEST;

    public QuicFragmentationProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, QuicProbeType.FRAGMENTATION, configSelector);
        register(QuicAnalyzedProperty.PROCESSES_SPLITTED_CLIENT_HELLO);
    }

    @Override
    public void executeTest() {
        processesSplittedClientHello = processesSplittedClientHello();
    }

    /** First ClientHello message in two CRYPTO frames and two Initial packets. */
    private TestResult processesSplittedClientHello() {
        Config config = configSelector.getTls13BaseConfig();

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createDynamicHelloWorkflow(config.getDefaultClientConnection());
        SendAction sendAction = (SendAction) trace.getFirstSendingAction();
        sendAction.setConfiguredQuicFrames(new CryptoFrame(250), new CryptoFrame(250));

        State state = new State(config, trace);
        executeState(state);

        return state.getWorkflowTrace().executedAsPlanned() ? TestResults.TRUE : TestResults.FALSE;
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(QuicAnalyzedProperty.PROCESSES_SPLITTED_CLIENT_HELLO, processesSplittedClientHello);
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProtocolTypeTrueRequirement<>(ProtocolType.QUIC);
    }

    @Override
    public void adjustConfig(ServerReport report) {}
}
