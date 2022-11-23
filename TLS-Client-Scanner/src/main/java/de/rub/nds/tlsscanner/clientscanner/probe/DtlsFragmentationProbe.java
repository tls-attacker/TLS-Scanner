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
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.result.DtlsFragmentationResult;

public class DtlsFragmentationProbe
        extends TlsClientProbe<
                ClientScannerConfig, ClientReport, DtlsFragmentationResult<ClientReport>> {

    private static final int INDIVIDUAL_TRANSPORT_PACKET_COOLDOWN = 200;

    public DtlsFragmentationProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
        super(executor, TlsProbeType.DTLS_FRAGMENTATION, scannerConfig);
    }

    @Override
    public DtlsFragmentationResult executeTest() {
        TestResult supportsDirectly = supportsFragmentationDirectly(false);
        TestResult supportsDirectlyIndPackets = supportsFragmentationDirectly(true);
        TestResult supportsAfterCookieExchange = supportsFragmentationAfterCookieExchange(false);
        TestResult supportsAfterCookieExchangeIndPackets =
                supportsFragmentationAfterCookieExchange(true);
        TestResult supportsWithExtension = supportsFragmentationWithExtension(false);
        TestResult supportsWithExtensionIndPackets = supportsFragmentationWithExtension(true);
        return new DtlsFragmentationResult(
                supportsDirectly,
                supportsDirectlyIndPackets,
                supportsAfterCookieExchange,
                supportsAfterCookieExchangeIndPackets,
                supportsWithExtension,
                supportsWithExtensionIndPackets);
    }

    private TestResult supportsFragmentationDirectly(boolean individualTransportPackets) {
        Config config = scannerConfig.createConfig();
        config.setDtlsMaximumFragmentLength(15);
        if (individualTransportPackets) {
            config.setCreateIndividualTransportPackets(true);
            config.setIndividualTransportPacketCooldown(INDIVIDUAL_TRANSPORT_PACKET_COOLDOWN);
        }

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new SendAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage(config)));

        State state = new State(config, trace);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult supportsFragmentationAfterCookieExchange(
            boolean individualTransportPackets) {
        Config config = scannerConfig.createConfig();
        if (individualTransportPackets) {
            config.setCreateIndividualTransportPackets(true);
            config.setIndividualTransportPacketCooldown(INDIVIDUAL_TRANSPORT_PACKET_COOLDOWN);
        }

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new SendAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new SendAction(new ServerHelloMessage(config)));
        SendAction action = new SendAction(new CertificateMessage());
        action.setFragments(
                new DtlsHandshakeMessageFragment(config, 20),
                new DtlsHandshakeMessageFragment(config, 20));
        trace.addTlsAction(action);
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

    private TestResult supportsFragmentationWithExtension(boolean individualTransportPackets) {
        Config config = scannerConfig.createConfig();
        config.setAddMaxFragmentLengthExtension(true);
        config.setDefaultMaxFragmentLength(MaxFragmentLength.TWO_11);
        if (individualTransportPackets) {
            config.setCreateIndividualTransportPackets(true);
            config.setIndividualTransportPacketCooldown(INDIVIDUAL_TRANSPORT_PACKET_COOLDOWN);
        }

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new SendAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new SendAction(new ServerHelloMessage(config)));
        SendAction action = new SendAction(new CertificateMessage());
        action.setFragments(
                new DtlsHandshakeMessageFragment(config, 20),
                new DtlsHandshakeMessageFragment(config, 20));
        trace.addTlsAction(action);
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

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return true;
    }

    @Override
    public DtlsFragmentationResult getCouldNotExecuteResult() {
        return new DtlsFragmentationResult(
                TestResults.COULD_NOT_TEST,
                TestResults.COULD_NOT_TEST,
                TestResults.COULD_NOT_TEST,
                TestResults.COULD_NOT_TEST,
                TestResults.COULD_NOT_TEST,
                TestResults.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(ClientReport report) {}
}
