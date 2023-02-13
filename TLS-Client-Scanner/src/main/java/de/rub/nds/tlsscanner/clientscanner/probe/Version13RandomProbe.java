/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.constants.TestResults;
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
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.probe.result.Version13RandomResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.Random;
import java.util.stream.Collectors;

public class Version13RandomProbe
        extends TlsClientProbe<ClientScannerConfig, ClientReport, Version13RandomResult> {

    private static final byte[] SERVER_RANDOM_12_POSTFIX = {
        0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01
    };
    private static final byte[] SERVER_RANDOM_PRE_12_POSTFIX = {
        0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00
    };

    private final Random random = new Random();

    public Version13RandomProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
        super(executor, TlsProbeType.VERSION_1_3_RANDOM_DOWNGRADE, scannerConfig);
    }

    @Override
    public Version13RandomResult executeTest() {
        boolean tls10Rejected = testIfDownGradeEnforcedProtocolVersion(ProtocolVersion.TLS10);
        boolean tls11Rejected = testIfDownGradeEnforcedProtocolVersion(ProtocolVersion.TLS11);
        boolean tls12Rejected = testIfDownGradeEnforcedProtocolVersion(ProtocolVersion.TLS12);
        if (tls10Rejected && tls11Rejected && tls12Rejected) {
            return new Version13RandomResult(TestResults.TRUE);
        }
        return new Version13RandomResult(TestResults.FALSE);
    }

    private boolean testIfDownGradeEnforcedProtocolVersion(ProtocolVersion version) {
        Config config = scannerConfig.createConfig();
        config.setHighestProtocolVersion(version);
        config.setDefaultSelectedProtocolVersion(version);
        config.setDefaultServerSupportedCipherSuites(
                CipherSuite.getImplemented().stream()
                        .filter(suite -> !suite.isTLS13())
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

        return WorkflowTraceUtil.didReceiveMessage(
                HandshakeMessageType.CERTIFICATE, state.getWorkflowTrace());
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        if (report.isProbeAlreadyExecuted(TlsProbeType.PROTOCOL_VERSION)) {
            boolean supportsTls10 =
                    report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_0) == TestResults.TRUE;
            boolean supportsTls11 =
                    report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_1) == TestResults.TRUE;
            boolean supportsTls12 =
                    report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_2) == TestResults.TRUE;
            boolean supportsTls13 =
                    report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3) == TestResults.TRUE;
            return supportsTls13 && (supportsTls10 || supportsTls11 || supportsTls12);
        } else {
            return false;
        }
    }

    @Override
    public Version13RandomResult getCouldNotExecuteResult() {
        return new Version13RandomResult(TestResults.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(ClientReport report) {}
}
