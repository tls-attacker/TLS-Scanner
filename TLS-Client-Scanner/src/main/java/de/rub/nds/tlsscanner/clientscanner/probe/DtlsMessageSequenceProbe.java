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
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeWriteMessageSequenceAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.result.DtlsMessageSequenceResult;

public class DtlsMessageSequenceProbe
        extends TlsClientProbe<
                ClientScannerConfig, ClientReport, DtlsMessageSequenceResult<ClientReport>> {

    public DtlsMessageSequenceProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
        super(executor, TlsProbeType.DTLS_MESSAGE_SEQUENCE_NUMBER, scannerConfig);
    }

    @Override
    public DtlsMessageSequenceResult executeTest() {
        return new DtlsMessageSequenceResult(
                acceptsStartedWithInvalidMessageNumber(),
                acceptsSkippedMessageNumbersOnce(),
                acceptsSkippedMessageNumbersMultiple(),
                acceptsRandomMessageNumbers());
    }

    private TestResult acceptsStartedWithInvalidMessageNumber() {
        Config config = scannerConfig.createConfig();

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ChangeWriteMessageSequenceAction(3));
        trace.addTlsAction(new SendAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new SendAction(new ServerHelloMessage(config)));
        trace.addTlsAction(new SendAction(new CertificateMessage()));
        trace.addTlsAction(new SendDynamicServerKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ServerHelloDoneMessage()));
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

        State state = new State(config, trace);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult acceptsSkippedMessageNumbersOnce() {
        Config config = scannerConfig.createConfig();

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultServerConnection());
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        trace.addTlsAction(new ChangeWriteMessageSequenceAction(4));
        trace.addTlsAction(new SendAction(new ServerHelloMessage(config)));
        trace.addTlsAction(new SendAction(new CertificateMessage()));
        trace.addTlsAction(new SendDynamicServerKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ServerHelloDoneMessage()));
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

        State state = new State(config, trace);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult acceptsSkippedMessageNumbersMultiple() {
        Config config = scannerConfig.createConfig();

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultServerConnection());
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        trace.addTlsAction(new ChangeWriteMessageSequenceAction(4));
        trace.addTlsAction(new SendAction(new ServerHelloMessage(config)));
        trace.addTlsAction(new SendAction(new CertificateMessage()));
        trace.addTlsAction(new SendDynamicServerKeyExchangeAction());
        trace.addTlsAction(new ChangeWriteMessageSequenceAction(8));
        trace.addTlsAction(new SendAction(new ServerHelloDoneMessage()));
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

        State state = new State(config, trace);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult acceptsRandomMessageNumbers() {
        Config config = scannerConfig.createConfig();

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultServerConnection());
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        trace.addTlsAction(new ChangeWriteMessageSequenceAction(8));
        trace.addTlsAction(new SendAction(new ServerHelloMessage(config)));
        trace.addTlsAction(new SendAction(new CertificateMessage()));
        trace.addTlsAction(new SendDynamicServerKeyExchangeAction());
        trace.addTlsAction(new ChangeWriteMessageSequenceAction(4));
        trace.addTlsAction(new SendAction(new ServerHelloDoneMessage()));
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

        State state = new State(config, trace);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return true;
    }

    @Override
    public DtlsMessageSequenceResult getCouldNotExecuteResult() {
        return new DtlsMessageSequenceResult(
                TestResults.COULD_NOT_TEST,
                TestResults.COULD_NOT_TEST,
                TestResults.COULD_NOT_TEST,
                TestResults.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(ClientReport report) {}
}
