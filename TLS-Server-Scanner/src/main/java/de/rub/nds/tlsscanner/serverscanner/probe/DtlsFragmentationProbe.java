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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
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
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.probe.result.DtlsFragmentationResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class DtlsFragmentationProbe extends TlsProbe<ServerScannerConfig, ServerReport, DtlsFragmentationResult> {

    private static int individualTransportPacketCooldown;

    public DtlsFragmentationProbe(ServerScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.DTLS_FRAGMENTATION, scannerConfig);
        this.individualTransportPacketCooldown = 200;
    }

    @Override
    public DtlsFragmentationResult executeTest() {
        TestResult supportsDirectly = supportsFragmentationDirectly(false);
        TestResult supportsDirectlyIndPackets = supportsFragmentationDirectly(true);
        TestResult supportsAfterCookieExchange = supportsFragmentationAfterCookieExchange(false);
        TestResult supportsAfterCookieExchangeIndPackets = supportsFragmentationAfterCookieExchange(true);
        TestResult supportsWithExtension = supportsFragmentationWithExtension(false);
        TestResult supportsWithExtensionIndPackets = supportsFragmentationWithExtension(true);
        return new DtlsFragmentationResult(supportsDirectly, supportsDirectlyIndPackets, supportsAfterCookieExchange,
            supportsAfterCookieExchangeIndPackets, supportsWithExtension, supportsWithExtensionIndPackets);
    }

    private TestResult supportsFragmentationDirectly(boolean individualTransportPackets) {
        Config config = getConfig();
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        config.setDtlsMaximumFragmentLength(150);
        if (individualTransportPackets) {
            config.setCreateIndividualTransportPackets(true);
            config.setIndividualTransportPacketCooldown(individualTransportPacketCooldown);
        }

        State state = new State(config);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, state.getWorkflowTrace())) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult supportsFragmentationAfterCookieExchange(boolean individualTransportPackets) {
        Config config = getConfig();
        if (individualTransportPackets) {
            config.setCreateIndividualTransportPackets(true);
            config.setIndividualTransportPacketCooldown(individualTransportPacketCooldown);
        }

        WorkflowTrace trace = new WorkflowConfigurationFactory(config)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        SendDynamicClientKeyExchangeAction action = new SendDynamicClientKeyExchangeAction();
        action.setFragments(new DtlsHandshakeMessageFragment(config, 20), new DtlsHandshakeMessageFragment(config, 20));
        trace.addTlsAction(action);
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(config), new FinishedMessage(config)));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage(config)));

        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult supportsFragmentationWithExtension(boolean individualTransportPackets) {
        Config config = getConfig();
        config.setAddMaxFragmentLengthExtension(true);
        config.setDefaultMaxFragmentLength(MaxFragmentLength.TWO_11);
        if (individualTransportPackets) {
            config.setCreateIndividualTransportPackets(true);
            config.setIndividualTransportPacketCooldown(individualTransportPacketCooldown);
        }

        WorkflowTrace trace = new WorkflowConfigurationFactory(config)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        SendDynamicClientKeyExchangeAction action = new SendDynamicClientKeyExchangeAction();
        action.setFragments(new DtlsHandshakeMessageFragment(config, 20), new DtlsHandshakeMessageFragment(config, 20));
        trace.addTlsAction(action);
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(config), new FinishedMessage(config)));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage(config)));

        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
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
    public boolean canBeExecuted(ServerReport report) {
        return true;
    }

    @Override
    public DtlsFragmentationResult getCouldNotExecuteResult() {
        return new DtlsFragmentationResult(TestResults.COULD_NOT_TEST, TestResults.COULD_NOT_TEST,
            TestResults.COULD_NOT_TEST, TestResults.COULD_NOT_TEST, TestResults.COULD_NOT_TEST,
            TestResults.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

}