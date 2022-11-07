/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.result.DtlsFragmentationResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class DtlsFragmentationProbe
        extends TlsServerProbe<
                ConfigSelector, ServerReport, DtlsFragmentationResult<ServerReport>> {

    private static final int INDIVIDUAL_TRANSPORT_PACKET_COOLDOWN = 200;

    public DtlsFragmentationProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.DTLS_FRAGMENTATION, configSelector);
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
        Config config = configSelector.getBaseConfig();
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        config.setDtlsMaximumFragmentLength(150);
        if (individualTransportPackets) {
            config.setCreateIndividualTransportPackets(true);
            config.setIndividualTransportPacketCooldown(INDIVIDUAL_TRANSPORT_PACKET_COOLDOWN);
        }

        State state = new State(config);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(
                HandshakeMessageType.SERVER_HELLO_DONE, state.getWorkflowTrace())) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult supportsFragmentationAfterCookieExchange(
            boolean individualTransportPackets) {
        Config config = configSelector.getBaseConfig();
        if (individualTransportPackets) {
            config.setCreateIndividualTransportPackets(true);
            config.setIndividualTransportPacketCooldown(INDIVIDUAL_TRANSPORT_PACKET_COOLDOWN);
        }

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        SendDynamicClientKeyExchangeAction action = new SendDynamicClientKeyExchangeAction();
        action.setFragments(
                new DtlsHandshakeMessageFragment(config, 20),
                new DtlsHandshakeMessageFragment(config, 20));
        trace.addTlsAction(action);
        trace.addTlsAction(
                new SendAction(new ChangeCipherSpecMessage(config), new FinishedMessage(config)));
        trace.addTlsAction(
                new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage(config)));

        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(
                HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult supportsFragmentationWithExtension(boolean individualTransportPackets) {
        Config config = configSelector.getBaseConfig();
        config.setAddMaxFragmentLengthExtension(true);
        config.setDefaultMaxFragmentLength(MaxFragmentLength.TWO_11);
        if (individualTransportPackets) {
            config.setCreateIndividualTransportPackets(true);
            config.setIndividualTransportPacketCooldown(INDIVIDUAL_TRANSPORT_PACKET_COOLDOWN);
        }

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        SendDynamicClientKeyExchangeAction action = new SendDynamicClientKeyExchangeAction();
        action.setFragments(
                new DtlsHandshakeMessageFragment(config, 20),
                new DtlsHandshakeMessageFragment(config, 20));
        trace.addTlsAction(action);
        trace.addTlsAction(
                new SendAction(new ChangeCipherSpecMessage(config), new FinishedMessage(config)));
        trace.addTlsAction(
                new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage(config)));

        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(
                HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
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
    public void adjustConfig(ServerReport report) {}
}
