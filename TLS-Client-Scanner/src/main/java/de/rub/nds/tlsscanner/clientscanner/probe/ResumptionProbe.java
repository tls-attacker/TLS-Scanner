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
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.probe.result.ResumptionResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.function.Function;

public class ResumptionProbe
        extends TlsClientProbe<ClientScannerConfig, ClientReport, ResumptionResult> {

    private TestResult supportsDtlsCookieExchangeInIdResumption;
    private TestResult supportsDtlsCookieExchangeInTicketResumption;

    public ResumptionProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
        super(executor, TlsProbeType.RESUMPTION, scannerConfig);
    }

    @Override
    public ResumptionResult executeTest() {
        Function<State, Integer> beforeTransportInitCallback =
                getParallelExecutor().getDefaultBeforeTransportInitCallback();
        String runCommand =
                scannerConfig.getRunCommand().strip()
                        + " "
                        + scannerConfig.getClientParameterDelegate().getResumptionOptions().strip();
        getParallelExecutor()
                .setDefaultBeforeTransportInitCallback(
                        scannerConfig.getRunCommandExecutionCallback(runCommand));

        ResumptionResult result;
        if (scannerConfig.getDtlsDelegate().isDTLS()) {
            supportsDtlsCookieExchangeInIdResumption =
                    getSupportsDtlsCookieExchangeInIdResumption();
            supportsDtlsCookieExchangeInTicketResumption =
                    getSupportsDtlsCookieExchangeInTicketResumption();
            result =
                    new ResumptionResult(
                            getSupportsIdResumption(),
                            getSupportsTicketResumption(),
                            supportsDtlsCookieExchangeInIdResumption,
                            supportsDtlsCookieExchangeInTicketResumption);
        } else {
            supportsDtlsCookieExchangeInIdResumption = TestResults.NOT_TESTED_YET;
            supportsDtlsCookieExchangeInTicketResumption = TestResults.NOT_TESTED_YET;
            result =
                    new ResumptionResult(
                            getSupportsIdResumption(),
                            getSupportsTicketResumption(),
                            supportsDtlsCookieExchangeInIdResumption,
                            supportsDtlsCookieExchangeInTicketResumption);
        }

        getParallelExecutor().setDefaultBeforeTransportInitCallback(beforeTransportInitCallback);
        return result;
    }

    private TestResult getSupportsDtlsCookieExchangeInIdResumption() {
        Config config = scannerConfig.createConfig();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER);
        addResetConnectionActions(trace);

        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));

        State state = new State(config, trace);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult getSupportsIdResumption() {
        Config config = scannerConfig.createConfig();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER);
        addResetConnectionActions(trace);

        config.setDtlsCookieExchange(supportsDtlsCookieExchangeInIdResumption == TestResults.TRUE);
        WorkflowTrace resumptionTrace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(WorkflowTraceType.RESUMPTION, RunningModeType.SERVER);
        trace.addTlsActions(resumptionTrace.getTlsActions());

        State state = new State(config, trace);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult getSupportsDtlsCookieExchangeInTicketResumption() {
        // TODO
        return TestResults.NOT_TESTED_YET;
    }

    private TestResult getSupportsTicketResumption() {
        // TODO
        return TestResults.NOT_TESTED_YET;
    }

    private void addResetConnectionActions(WorkflowTrace trace) {
        AlertMessage alert = new AlertMessage();
        alert.setConfig(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);
        trace.addTlsAction(new SendAction(alert));
        trace.addTlsAction(new ResetConnectionAction());
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return scannerConfig.getClientParameterDelegate().getResumptionOptions() != null;
    }

    @Override
    public ResumptionResult getCouldNotExecuteResult() {
        return new ResumptionResult(
                TestResults.COULD_NOT_TEST,
                TestResults.COULD_NOT_TEST,
                TestResults.COULD_NOT_TEST,
                TestResults.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(ClientReport report) {}
}
