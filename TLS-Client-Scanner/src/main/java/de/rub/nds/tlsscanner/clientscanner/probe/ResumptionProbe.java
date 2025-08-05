/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
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
import de.rub.nds.tlsscanner.clientscanner.probe.requirements.ClientOptionsRequirement;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeFalseRequirement;
import java.util.function.Function;

public class ResumptionProbe extends TlsClientProbe {

    private TestResult supportsResumption = TestResults.COULD_NOT_TEST;
    private TestResult supportsSessionTicketResumption = TestResults.COULD_NOT_TEST;
    private TestResult supportsDtlsCookieExchangeInResumption = TestResults.COULD_NOT_TEST;
    private TestResult supportsDtlsCookieExchangeInSessionTicketResumption =
            TestResults.COULD_NOT_TEST;

    public ResumptionProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
        super(executor, TlsProbeType.RESUMPTION, scannerConfig);
        register(
                TlsAnalyzedProperty.SUPPORTS_SESSION_ID_RESUMPTION,
                TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_RESUMPTION,
                TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_ID_RESUMPTION,
                TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_TICKET_RESUMPTION);
    }

    @Override
    protected void executeTest() {
        Function<State, Integer> beforeTransportInitCallback =
                getParallelExecutor().getDefaultBeforeTransportInitCallback();
        String runCommand =
                scannerConfig.getRunCommand().strip()
                        + " "
                        + scannerConfig.getClientParameterDelegate().getResumptionOptions().strip();
        getParallelExecutor()
                .setDefaultBeforeTransportInitCallback(
                        scannerConfig.getRunCommandExecutionCallback(runCommand));

        supportsDtlsCookieExchangeInResumption =
                scannerConfig.getDtlsDelegate().isDTLS()
                        ? getSupportsDtlsCookieExchangeInIdResumption()
                        : TestResults.NOT_TESTED_YET;
        supportsDtlsCookieExchangeInSessionTicketResumption =
                scannerConfig.getDtlsDelegate().isDTLS()
                        ? getSupportsDtlsCookieExchangeInTicketResumption()
                        : TestResults.NOT_TESTED_YET;
        supportsResumption = getSupportsIdResumption();
        supportsSessionTicketResumption = getSupportsTicketResumption();

        getParallelExecutor().setDefaultBeforeTransportInitCallback(beforeTransportInitCallback);
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

        config.setDtlsCookieExchange(supportsDtlsCookieExchangeInResumption == TestResults.TRUE);
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
    public void adjustConfig(ClientReport report) {}

    @Override
    protected void mergeData(ClientReport report) {
        put(TlsAnalyzedProperty.SUPPORTS_SESSION_ID_RESUMPTION, supportsResumption);
        put(
                TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_RESUMPTION,
                supportsSessionTicketResumption);
        put(
                TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_ID_RESUMPTION,
                supportsDtlsCookieExchangeInResumption);
        put(
                TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_TICKET_RESUMPTION,
                supportsDtlsCookieExchangeInSessionTicketResumption);
    }

    @Override
    public Requirement<ClientReport> getRequirements() {
        return new ProtocolTypeFalseRequirement<ClientReport>(ProtocolType.DTLS)
                .and(new ClientOptionsRequirement(scannerConfig, getType()));
    }
}
