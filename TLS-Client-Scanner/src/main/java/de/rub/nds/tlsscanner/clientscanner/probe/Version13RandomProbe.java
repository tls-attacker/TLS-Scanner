/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.PropertyTrueRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeFalseRequirement;
import java.util.Random;
import java.util.stream.Collectors;

public class Version13RandomProbe extends TlsClientProbe {

    private static final byte[] SERVER_RANDOM_12_POSTFIX = {
        0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01
    };
    private static final byte[] SERVER_RANDOM_PRE_12_POSTFIX = {
        0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00
    };

    private TestResult hasDowngradeProtection = TestResults.COULD_NOT_TEST;

    private final Random random = new Random();

    public Version13RandomProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
        super(executor, TlsProbeType.VERSION_1_3_RANDOM_DOWNGRADE, scannerConfig);
        register(TlsAnalyzedProperty.TLS_1_3_DOWNGRADE_PROTECTION);
    }

    @Override
    protected void executeTest() {
        boolean tls10Rejected = testIfDownGradeEnforcedProtocolVersion(ProtocolVersion.TLS10);
        boolean tls11Rejected = testIfDownGradeEnforcedProtocolVersion(ProtocolVersion.TLS11);
        boolean tls12Rejected = testIfDownGradeEnforcedProtocolVersion(ProtocolVersion.TLS12);
        if (tls10Rejected && tls11Rejected && tls12Rejected) {
            hasDowngradeProtection = TestResults.TRUE;
        } else {
            hasDowngradeProtection = TestResults.FALSE;
        }
    }

    private boolean testIfDownGradeEnforcedProtocolVersion(ProtocolVersion version) {
        Config config = scannerConfig.createConfig();
        config.setHighestProtocolVersion(version);
        config.setDefaultSelectedProtocolVersion(version);
        config.setDefaultServerSupportedCipherSuites(
                CipherSuite.getImplemented().stream()
                        .filter(suite -> !suite.isTls13())
                        .collect(Collectors.toList()));

        // patch randomness
        byte[] serverRandomPostfix =
                version == ProtocolVersion.TLS12
                        ? SERVER_RANDOM_12_POSTFIX
                        : SERVER_RANDOM_PRE_12_POSTFIX;
        byte[] serverRandomPrefix =
                new byte[HandshakeByteLength.RANDOM - serverRandomPostfix.length];
        byte[] serverRandom = new byte[HandshakeByteLength.RANDOM];
        random.nextBytes(serverRandomPrefix);
        System.arraycopy(serverRandomPrefix, 0, serverRandom, 0, serverRandomPrefix.length);
        System.arraycopy(
                serverRandomPostfix,
                0,
                serverRandom,
                serverRandomPrefix.length,
                serverRandomPostfix.length);
        config.setDefaultServerRandom(serverRandom);
        config.setUseFreshRandom(false);

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(WorkflowTraceType.HELLO, RunningModeType.SERVER);
        trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

        State state = new State(config, trace);
        executeState(state);

        return WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.CERTIFICATE);
    }

    @Override
    public void adjustConfig(ClientReport report) {}

    @Override
    public Requirement<ClientReport> getRequirements() {
        return new ProtocolTypeFalseRequirement<ClientReport>(ProtocolType.DTLS)
                .and(new ProbeRequirement<>(TlsProbeType.PROTOCOL_VERSION))
                .and(new PropertyTrueRequirement<>(TlsAnalyzedProperty.SUPPORTS_TLS_1_3))
                .and(
                        new PropertyTrueRequirement<ClientReport>(
                                        TlsAnalyzedProperty.SUPPORTS_TLS_1_0)
                                .or(
                                        new PropertyTrueRequirement<>(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_1))
                                .or(
                                        new PropertyTrueRequirement<>(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2)));
    }

    @Override
    protected void mergeData(ClientReport report) {
        put(TlsAnalyzedProperty.TLS_1_3_DOWNGRADE_PROTECTION, hasDowngradeProtection);
    }
}
