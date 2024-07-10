/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.quic;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.quic.frame.CryptoFrame;
import de.rub.nds.tlsattacker.core.quic.frame.HandshakeDoneFrame;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveQuicTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
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
    private TestResult overwritesReceivedCryptoFrames = TestResults.COULD_NOT_TEST;

    public QuicFragmentationProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, QuicProbeType.FRAGMENTATION, configSelector);
        register(
                QuicAnalyzedProperty.PROCESSES_SPLITTED_CLIENT_HELLO,
                QuicAnalyzedProperty.OVERWRITES_RECEIVED_CRYPTO_FRAMES);
    }

    @Override
    public void executeTest() {
        processesSplittedClientHello = processesSplittedClientHello();
        overwritesReceivedCryptoFrames = overwritesReceivedCryptoFrames();
    }

    /** ClientHello message in two CRYPTO frames. */
    private TestResult processesSplittedClientHello() {
        Config config = configSelector.getTls13BaseConfig();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        SendAction sendAction = new SendAction();
        sendAction.setConfiguredMessages(new ClientHelloMessage(config));
        sendAction.setConfiguredQuicFrames(new CryptoFrame(50), new CryptoFrame(50));
        trace.addTlsAction(sendAction);
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

        State state = new State(config, trace);
        executeState(state);
        return state.getWorkflowTrace().executedAsPlanned() ? TestResults.TRUE : TestResults.FALSE;
    }

    /**
     * ClientHello message in two CRYPTO frames. The second frame overlaps the last byte of the
     * first frame. Overwrites the first cipher suite from TLS_NULL_WITH_NULL_NULL to
     * TLS_AES_128_GCM_SHA256. (Our transcript contains TLS_AES_128_GCM_SHA256.)
     */
    private TestResult overwritesReceivedCryptoFrames() {
        Config config = configSelector.getTls13BaseConfig();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        SendAction sendAction = new SendAction();
        sendAction.setConfiguredMessages(new ClientHelloMessage(config));
        CryptoFrame frame1 = new CryptoFrame(43);
        frame1.setCryptoData(Modifiable.xor(new byte[] {(byte) 0x13, (byte) 0x01}, 41));
        CryptoFrame frame2 = new CryptoFrame(400);
        frame2.setOffset(Modifiable.sub(Long.valueOf("2")));
        frame2.setLength(Modifiable.add(Long.valueOf("2")));
        frame2.setCryptoData(Modifiable.insert(new byte[] {(byte) 0x13, (byte) 0x01}, 0));
        sendAction.setConfiguredQuicFrames(frame1, frame2);
        trace.addTlsAction(sendAction);
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
        trace.addTlsAction(new SendAction(new FinishedMessage()));
        trace.addTlsAction(new ReceiveQuicTillAction(new HandshakeDoneFrame()));

        State state = new State(config, trace);
        executeState(state);
        return state.getWorkflowTrace().executedAsPlanned() ? TestResults.TRUE : TestResults.FALSE;
    }

    /**
     * ClientHello message in two CRYPTO frames. The second frame overlaps the last byte of the
     * first frame. Overwrites the first cipher suite from TLS_AES_128_GCM_SHA256 to
     * TLS_NULL_WITH_NULL_NULL and enforce TLS_AES_128_GCM_SHA256 as the negotiated cipher suite.
     * (Our transcript contains TLS_AES_128_GCM_SHA256.)
     */
    private TestResult overwritesReceivedCryptoFramesTestCase2() {
        Config config = configSelector.getTls13BaseConfig();
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        config.setEnforceSettings(true);

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        SendAction sendAction = new SendAction();
        sendAction.setConfiguredMessages(new ClientHelloMessage(config));
        CryptoFrame frame1 = new CryptoFrame(43);
        CryptoFrame frame2 = new CryptoFrame(400);
        frame2.setOffset(Modifiable.sub(Long.valueOf("2")));
        frame2.setLength(Modifiable.add(Long.valueOf("2")));
        frame2.setCryptoData(Modifiable.insert(new byte[] {(byte) 0x00, (byte) 0x00}, 0));
        sendAction.setConfiguredQuicFrames(frame1, frame2);
        trace.addTlsAction(sendAction);
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
        trace.addTlsAction(new SendAction(new FinishedMessage()));
        trace.addTlsAction(new ReceiveQuicTillAction(new HandshakeDoneFrame()));

        State state = new State(config, trace);
        executeState(state);
        return state.getWorkflowTrace().executedAsPlanned() ? TestResults.TRUE : TestResults.FALSE;
    }

    /**
     * ClientHello message in two CRYPTO frames. The second frame overlaps the last byte of the
     * first frame. Overwrites the first cipher suite from TLS_AES_128_GCM_SHA256 to
     * TLS_NULL_WITH_NULL_NULL and enforce TLS_AES_256_GCM_SHA384 as the negotiated cipher suite.
     * (Our transcript contains TLS_AES_128_GCM_SHA256.)
     */
    private TestResult overwritesReceivedCryptoFramesTest3() {
        Config config = configSelector.getTls13BaseConfig();
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_AES_256_GCM_SHA384);
        config.setEnforceSettings(true);

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        SendAction sendAction = new SendAction();
        sendAction.setConfiguredMessages(new ClientHelloMessage(config));
        CryptoFrame frame1 = new CryptoFrame(43);
        CryptoFrame frame2 = new CryptoFrame(400);
        frame2.setOffset(Modifiable.sub(Long.valueOf("2")));
        frame2.setLength(Modifiable.add(Long.valueOf("2")));
        frame2.setCryptoData(Modifiable.insert(new byte[] {(byte) 0x00, (byte) 0x00}, 0));
        sendAction.setConfiguredQuicFrames(frame1, frame2);
        trace.addTlsAction(sendAction);
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
        trace.addTlsAction(new SendAction(new FinishedMessage()));
        trace.addTlsAction(new ReceiveQuicTillAction(new HandshakeDoneFrame()));

        State state = new State(config, trace);
        executeState(state);
        return state.getWorkflowTrace().executedAsPlanned() ? TestResults.TRUE : TestResults.FALSE;
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(QuicAnalyzedProperty.PROCESSES_SPLITTED_CLIENT_HELLO, processesSplittedClientHello);
        put(QuicAnalyzedProperty.OVERWRITES_RECEIVED_CRYPTO_FRAMES, overwritesReceivedCryptoFrames);
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProtocolTypeTrueRequirement<>(ProtocolType.QUIC);
    }

    @Override
    public void adjustConfig(ServerReport report) {}
}
