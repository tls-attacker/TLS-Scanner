/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.quic;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.quic.constants.QuicVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.QuicProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.quic.QuicTls12HandshakeResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import de.rub.nds.tlsscanner.serverscanner.selector.DefaultConfigProfile;

public class QuicTls12HandshakeProbe
        extends QuicServerProbe<ConfigSelector, ServerReport, QuicTls12HandshakeResult> {

    public QuicTls12HandshakeProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, QuicProbeType.TLS12_HANDSHAKE, configSelector);
    }

    @Override
    public QuicTls12HandshakeResult executeTest() {
        Config config =
                configSelector.getConfigForProfile(
                        ConfigSelector.DEFAULT_CONFIG,
                        DefaultConfigProfile.HIGHLY_REDUCED_CIPHERSUITES);
        config.setExpectHandshakeDoneQuicFrame(true);
        config.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        config.setQuicVersion(QuicVersion.VERSION_1.getByteValue());
        config.setHighestProtocolVersion(ProtocolVersion.TLS12);
        config.setDefaultSelectedProtocolVersion(ProtocolVersion.TLS12);
        config.setSupportedVersions(ProtocolVersion.TLS12);
        config.setDefaultLastRecordProtocolVersion(ProtocolVersion.TLS12);
        State state = new State(config);
        executeState(state);
        if (!state.getWorkflowTrace().executedAsPlanned()) {
            return new QuicTls12HandshakeResult(
                    false, state.getContext().getQuicContext().getReceivedConnectionCloseFrame());
        } else {
            return new QuicTls12HandshakeResult(true);
        }
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return true;
    }

    @Override
    public QuicTls12HandshakeResult getCouldNotExecuteResult() {
        return null;
    }

    @Override
    public void adjustConfig(ServerReport report) {}
}
