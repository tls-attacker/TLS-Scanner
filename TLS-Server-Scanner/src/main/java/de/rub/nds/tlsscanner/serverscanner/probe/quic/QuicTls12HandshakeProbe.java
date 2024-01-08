/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.quic;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.quic.frame.ConnectionCloseFrame;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.QuicAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.QuicProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import de.rub.nds.tlsscanner.serverscanner.selector.DefaultConfigProfile;

public class QuicTls12HandshakeProbe extends QuicServerProbe {

    private boolean handshakeCompleted;
    private ConnectionCloseFrame connectionCloseFrame;

    public QuicTls12HandshakeProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, QuicProbeType.TLS12_HANDSHAKE, configSelector);
        register(
                QuicAnalyzedProperty.TLS12_HANDSHAKE_DONE,
                QuicAnalyzedProperty.TLS12_HANDSHAKE_CONNECTION_CLOSE_FRAME);
    }

    @Override
    public void executeTest() {
        Config config =
                configSelector.getConfigForProfile(
                        ConfigSelector.DEFAULT_CONFIG,
                        DefaultConfigProfile.HIGHLY_REDUCED_CIPHERSUITES);
        config.setExpectHandshakeDoneQuicFrame(true);
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HANDSHAKE);
        config.setHighestProtocolVersion(ProtocolVersion.TLS12);
        config.setDefaultSelectedProtocolVersion(ProtocolVersion.TLS12);
        config.setSupportedVersions(ProtocolVersion.TLS12);
        config.setDefaultLastRecordProtocolVersion(ProtocolVersion.TLS12);

        State state = new State(config);
        executeState(state);
        this.handshakeCompleted = state.getWorkflowTrace().executedAsPlanned();
        this.connectionCloseFrame =
                state.getContext().getQuicContext().getReceivedConnectionCloseFrame();
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(
                QuicAnalyzedProperty.TLS12_HANDSHAKE_DONE,
                handshakeCompleted ? TestResults.TRUE : TestResults.FALSE);
        put(QuicAnalyzedProperty.TLS12_HANDSHAKE_CONNECTION_CLOSE_FRAME, connectionCloseFrame);
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProtocolTypeTrueRequirement<>(ProtocolType.QUIC);
    }

    @Override
    public void adjustConfig(ServerReport report) {}
}
