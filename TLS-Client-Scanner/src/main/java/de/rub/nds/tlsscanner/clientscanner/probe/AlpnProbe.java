/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.probe.result.AlpnResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.List;
import java.util.function.Function;

public class AlpnProbe extends TlsClientProbe<ClientScannerConfig, ClientReport, AlpnResult> {

    private static final String ALPN_FAKE_PROTOCOL = "This is not an ALPN Protocol";

    public AlpnProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
        super(executor, TlsProbeType.ALPN, scannerConfig);
    }

    @Override
    public AlpnResult executeTest() {
        Function<State, Integer> beforeTransportInitCallback =
                getParallelExecutor().getDefaultBeforeTransportInitCallback();
        String runCommand =
                scannerConfig.getRunCommand().strip()
                        + " "
                        + scannerConfig.getClientParameterDelegate().getAlpnOptions().strip();
        getParallelExecutor()
                .setDefaultBeforeTransportInitCallback(
                        scannerConfig.getRunCommandExecutionCallback(runCommand));

        AlpnResult result = new AlpnResult(getAdvertisedAlpnProtocols(), supportsStrictAlpn());

        getParallelExecutor().setDefaultBeforeTransportInitCallback(beforeTransportInitCallback);
        return result;
    }

    private List<String> getAdvertisedAlpnProtocols() {
        Config config = scannerConfig.createConfig();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultServerConnection());
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        State state = new State(config, trace);
        executeState(state);

        if (state.getWorkflowTrace().executedAsPlanned()) {
            return state.getTlsContext().getProposedAlpnProtocols();
        } else {
            return null;
        }
    }

    private TestResult supportsStrictAlpn() {
        Config config = scannerConfig.createConfig();
        config.setAddAlpnExtension(true);
        config.setDefaultSelectedAlpnProtocol(ALPN_FAKE_PROTOCOL);
        config.setEnforceSettings(true);

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.SERVER);
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

        State state = new State(config, trace);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            return TestResults.FALSE;
        } else {
            return TestResults.TRUE;
        }
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return scannerConfig.getClientParameterDelegate().getAlpnOptions() != null;
    }

    @Override
    public AlpnResult getCouldNotExecuteResult() {
        return new AlpnResult(null, TestResults.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(ClientReport report) {}
}
