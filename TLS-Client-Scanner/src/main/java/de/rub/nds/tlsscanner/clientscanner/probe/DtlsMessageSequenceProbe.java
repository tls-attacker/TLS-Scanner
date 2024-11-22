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
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;

public class DtlsMessageSequenceProbe extends TlsClientProbe {

    private TestResult acceptsStartedWithInvalidMessageNumber = TestResults.COULD_NOT_TEST;
    private TestResult acceptsSkippedMessageNumbersOnce = TestResults.COULD_NOT_TEST;
    private TestResult acceptsSkippedMessageNumbersMultiple = TestResults.COULD_NOT_TEST;
    private TestResult acceptsRandomMessageNumbers = TestResults.COULD_NOT_TEST;

    public DtlsMessageSequenceProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
        super(executor, TlsProbeType.DTLS_MESSAGE_SEQUENCE_NUMBER, scannerConfig);
        register(
                TlsAnalyzedProperty.ACCEPTS_STARTED_WITH_INVALID_MESSAGE_SEQUENCE,
                TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_ONCE,
                TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE,
                TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES,
                TlsAnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS);
    }

    @Override
    protected void executeTest() {
        acceptsStartedWithInvalidMessageNumber = acceptsStartedWithInvalidMessageNumber();
        acceptsSkippedMessageNumbersOnce = acceptsSkippedMessageNumbersOnce();
        acceptsSkippedMessageNumbersMultiple = acceptsSkippedMessageNumbersMultiple();
        acceptsRandomMessageNumbers = acceptsRandomMessageNumbers();
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
    public void adjustConfig(ClientReport report) {}

    @Override
    protected void mergeData(ClientReport report) {
        put(
                TlsAnalyzedProperty.ACCEPTS_STARTED_WITH_INVALID_MESSAGE_SEQUENCE,
                acceptsStartedWithInvalidMessageNumber);
        put(
                TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_ONCE,
                acceptsSkippedMessageNumbersOnce);
        put(
                TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE,
                acceptsSkippedMessageNumbersMultiple);
        put(TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES, acceptsRandomMessageNumbers);
        if (acceptsSkippedMessageNumbersOnce == TestResults.FALSE
                && acceptsSkippedMessageNumbersMultiple == TestResults.FALSE
                && acceptsRandomMessageNumbers == TestResults.FALSE) {
            put(TlsAnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS, TestResults.FALSE);
        } else if (acceptsSkippedMessageNumbersOnce == TestResults.TRUE
                || acceptsSkippedMessageNumbersMultiple == TestResults.TRUE
                || acceptsRandomMessageNumbers == TestResults.TRUE) {
            put(TlsAnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS, TestResults.TRUE);
        } else {
            put(TlsAnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS, TestResults.COULD_NOT_TEST);
        }
    }

    @Override
    public Requirement<ClientReport> getRequirements() {
        return new ProtocolTypeTrueRequirement<>(ProtocolType.DTLS);
    }
}
