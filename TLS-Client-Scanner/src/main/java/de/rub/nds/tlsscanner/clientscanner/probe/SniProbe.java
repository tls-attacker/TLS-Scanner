/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.NameType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.probe.result.SniResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.function.Function;

public class SniProbe extends TlsClientProbe<ClientScannerConfig, ClientReport, SniResult> {

    private static final String SNI_CLIENT_EXPECTED = "tls-attackerhost.com";
    private static final String SNI_FAKE_NAME = "notarealtls-attackerhost.com";

    public SniProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
        super(executor, TlsProbeType.SNI, scannerConfig);
    }

    @Override
    public SniResult executeTest() {
        Function<State, Integer> beforeTransportInitCallback =
                getParallelExecutor().getDefaultBeforeTransportInitCallback();
        String runCommand =
                scannerConfig.getRunCommand().strip()
                        + " "
                        + scannerConfig
                                .getClientParameterDelegate()
                                .getSniOptions(SNI_CLIENT_EXPECTED)
                                .strip();
        getParallelExecutor()
                .setDefaultBeforeTransportInitCallback(
                        scannerConfig.getRunCommandExecutionCallback(runCommand));

        SniResult result = new SniResult(supportsStrictSni(), requiresSni());

        getParallelExecutor().setDefaultBeforeTransportInitCallback(beforeTransportInitCallback);
        return result;
    }

    private TestResult supportsStrictSni() {
        Config config = scannerConfig.createConfig();
        config.setAddServerNameIndicationExtension(true);
        config.setDefaultSniHostnames(
                new LinkedList<>(
                        Arrays.asList(
                                new ServerNamePair(
                                        NameType.HOST_NAME.getValue(),
                                        SNI_FAKE_NAME.getBytes(Charset.forName("ASCII"))))));

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

    private TestResult requiresSni() {
        Config config = scannerConfig.createConfig();
        config.setAddServerNameIndicationExtension(false);

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
        return scannerConfig.getClientParameterDelegate().getSniOptions(SNI_CLIENT_EXPECTED)
                != null;
    }

    @Override
    public SniResult getCouldNotExecuteResult() {
        return new SniResult(TestResults.COULD_NOT_TEST, TestResults.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(ClientReport report) {}
}
