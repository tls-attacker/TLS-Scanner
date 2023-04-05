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
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.quic.constants.QuicVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.QuicProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.quic.QuicConnectionMigrationResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class QuicConnectionMigrationProbe
        extends QuicServerProbe<ConfigSelector, ServerReport, QuicConnectionMigrationResult> {

    private static final Logger LOGGER = LogManager.getLogger();

    public QuicConnectionMigrationProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, QuicProbeType.CONNECTION_MIGRATION, configSelector);
    }

    @Override
    public QuicConnectionMigrationResult executeTest() {
        QuicConnectionMigrationResult result = new QuicConnectionMigrationResult();

        Config config = configSelector.getTls13BaseConfig();
        config.setExpectHandshakeDoneQuicFrame(true);
        config.setWorkflowTraceType(WorkflowTraceType.QUIC_PORT_CONNECTION_MIGRATION);
        config.setQuicVersion(QuicVersion.VERSION_1.getByteValue());
        State state = new State(config);
        executeState(state);

        result.setPortConnectionMigrationSuccessful(state.getWorkflowTrace().executedAsPlanned());

        if (config.getDefaultClientConnection().getIpv6() != null) {
            result.setIpv6Address(config.getDefaultClientConnection().getIpv6());
            config.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
            OutboundConnection ipv6Connection =
                    new OutboundConnection(config.getDefaultClientConnection());
            ipv6Connection.setUseIpv6(true);
            config.setDefaultClientConnection(ipv6Connection);
            state = new State(config);
            executeState(state);
            result.setIpv6HandshakeSuccessful(state.getWorkflowTrace().executedAsPlanned());

            if (state.getWorkflowTrace().executedAsPlanned()) {
                config.setWorkflowTraceType(WorkflowTraceType.QUIC_IPV6_CONNECTION_MIGRATION);
                state = new State(config);
                executeState(state);
                result.setIpv6ConnectionMigrationSuccessful(
                        state.getWorkflowTrace().executedAsPlanned());
            } else {
                result.setIpv6ConnectionMigrationSuccessful(false);
            }
        } else {
            result.setIpv6HandshakeSuccessful(false);
            result.setIpv6ConnectionMigrationSuccessful(false);
        }

        return result;
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return true;
    }

    @Override
    public QuicConnectionMigrationResult getCouldNotExecuteResult() {
        return null;
    }

    @Override
    public void adjustConfig(ServerReport report) {}
}
