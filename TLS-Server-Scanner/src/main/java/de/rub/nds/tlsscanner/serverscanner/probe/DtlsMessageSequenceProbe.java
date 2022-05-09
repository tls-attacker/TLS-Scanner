/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeContextValueAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class DtlsMessageSequenceProbe extends TlsProbe<ServerScannerConfig, ServerReport> {

    private TestResult acceptsStartedWithInvalidMessageNumber;
    private TestResult acceptsSkippedMessageNumbersOnce;
    private TestResult acceptsSkippedMessageNumbersMultiple;
    private TestResult acceptsRandomMessageNumbers;

    public DtlsMessageSequenceProbe(ServerScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.DTLS_MESSAGE_SEQUENCE_NUMBER, scannerConfig);
        super.register(TlsAnalyzedProperty.ACCEPTS_STARTED_WITH_INVALID_MESSAGE_SEQUENCE);
        super.register(TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_ONCE);
        super.register(TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE);
        super.register(TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES);
        super.register(TlsAnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS);
    }

    @Override
    public void executeTest() {
        this.acceptsStartedWithInvalidMessageNumber = acceptsStartedWithInvalidMessageNumber();
        this.acceptsSkippedMessageNumbersOnce = acceptsSkippedMessageNumbersOnce();
        this.acceptsSkippedMessageNumbersMultiple = acceptsSkippedMessageNumbersMultiple();
        this.acceptsRandomMessageNumbers = acceptsRandomMessageNumbers();
    }

    private TestResult acceptsRandomMessageNumbers() {
        Config config = getConfig();
        WorkflowTrace trace =
            new WorkflowConfigurationFactory(config).createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new ChangeContextValueAction<>("dtlsWriteHandshakeMessageSequence", 8));
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        trace.addTlsAction(new ChangeContextValueAction<>("dtlsWriteHandshakeMessageSequence", 4));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(config), new FinishedMessage(config)));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(config), new FinishedMessage(config)));

        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult acceptsSkippedMessageNumbersMultiple() {
        Config config = getConfig();
        WorkflowTrace trace =
            new WorkflowConfigurationFactory(config).createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new ChangeContextValueAction<>("dtlsWriteHandshakeMessageSequence", 4));
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        trace.addTlsAction(new ChangeContextValueAction<>("dtlsWriteHandshakeMessageSequence", 8));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(config), new FinishedMessage(config)));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(config), new FinishedMessage(config)));

        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult acceptsSkippedMessageNumbersOnce() {
        Config config = getConfig();
        WorkflowTrace trace =
            new WorkflowConfigurationFactory(config).createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new ChangeContextValueAction<>("dtlsWriteHandshakeMessageSequence", 4));
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(config), new FinishedMessage(config)));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(config), new FinishedMessage(config)));

        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult acceptsStartedWithInvalidMessageNumber() {
        Config config = getConfig();
        WorkflowTrace trace =
            new WorkflowConfigurationFactory(config).createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(0, new ChangeContextValueAction<>("dtlsWriteHandshakeMessageSequence", 3));
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));

        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, state.getWorkflowTrace())) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private Config getConfig() {
        Config config = getScannerConfig().createConfig();
        config.setHighestProtocolVersion(ProtocolVersion.DTLS12);
        List<CipherSuite> ciphersuites = new LinkedList<>();
        ciphersuites.addAll(Arrays.asList(CipherSuite.values()));
        ciphersuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        ciphersuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        config.setDefaultClientSupportedCipherSuites(ciphersuites);
        List<CompressionMethod> compressionList = new ArrayList<>(Arrays.asList(CompressionMethod.values()));
        config.setDefaultClientSupportedCompressionMethods(compressionList);
        config.setEnforceSettings(false);
        config.setQuickReceive(true);
        config.setEarlyStop(true);
        config.setStopReceivingAfterFatal(true);
        config.setStopActionsAfterFatal(true);
        config.setStopActionsAfterIOException(true);
        config.setAddECPointFormatExtension(true);
        config.setAddEllipticCurveExtension(true);
        config.setAddServerNameIndicationExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        return config;
    }

    @Override
    public DtlsMessageSequenceProbe getCouldNotExecuteResult() {
        this.acceptsStartedWithInvalidMessageNumber = this.acceptsSkippedMessageNumbersOnce =
            this.acceptsSkippedMessageNumbersMultiple = this.acceptsRandomMessageNumbers = TestResults.COULD_NOT_TEST;
        return this;
    }

    @Override
    protected Requirement getRequirements(ServerReport report) {
        return ProbeRequirement.NO_REQUIREMENT;
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

    @Override
    protected void mergeData(ServerReport report) {
        super.put(TlsAnalyzedProperty.ACCEPTS_STARTED_WITH_INVALID_MESSAGE_SEQUENCE,
            this.acceptsStartedWithInvalidMessageNumber);
        super.put(TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_ONCE, acceptsSkippedMessageNumbersOnce);
        super.put(TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE,
            this.acceptsSkippedMessageNumbersMultiple);
        super.put(TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES, acceptsRandomMessageNumbers);
        if (this.acceptsSkippedMessageNumbersOnce == TestResults.FALSE
            && this.acceptsSkippedMessageNumbersMultiple == TestResults.FALSE
            && this.acceptsRandomMessageNumbers == TestResults.FALSE) {
            super.put(TlsAnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS, TestResults.FALSE);
        } else
            super.put(TlsAnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS, TestResults.TRUE);
    }
}
