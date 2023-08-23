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
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.quic.constants.QuicVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.QuicProbeType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class QuicConnectionMigrationProbe extends QuicServerProbe {

    private boolean portConnectionMigrationSuccessful;
    private String ipv6Address;
    private boolean ipv6HandshakeSuccessful;
    private boolean ipv6ConnectionMigrationSuccessful;

    private static final Logger LOGGER = LogManager.getLogger();

    public QuicConnectionMigrationProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, QuicProbeType.CONNECTION_MIGRATION, configSelector);
    }

    @Override
    public void executeTest() {

        Config config = configSelector.getTls13BaseConfig();
        config.setExpectHandshakeDoneQuicFrame(true);
        config.setWorkflowTraceType(WorkflowTraceType.QUIC_PORT_CONNECTION_MIGRATION);
        config.setQuicVersion(QuicVersion.VERSION_1.getByteValue());
        State state = new State(config);
        executeState(state);

        portConnectionMigrationSuccessful = state.getWorkflowTrace().executedAsPlanned();

        if (config.getDefaultClientConnection().getIpv6() != null) {
            ipv6Address = config.getDefaultClientConnection().getIpv6();
            config.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
            OutboundConnection ipv6Connection =
                    new OutboundConnection(config.getDefaultClientConnection());
            ipv6Connection.setUseIpv6(true);
            config.setDefaultClientConnection(ipv6Connection);
            state = new State(config);
            executeState(state);
            ipv6HandshakeSuccessful = state.getWorkflowTrace().executedAsPlanned();

            if (state.getWorkflowTrace().executedAsPlanned()) {
                config.setWorkflowTraceType(WorkflowTraceType.QUIC_IPV6_CONNECTION_MIGRATION);
                state = new State(config);
                executeState(state);
                ipv6ConnectionMigrationSuccessful = state.getWorkflowTrace().executedAsPlanned();
            } else {
                ipv6ConnectionMigrationSuccessful = false;
            }
        } else {
            ipv6HandshakeSuccessful = false;
            ipv6ConnectionMigrationSuccessful = false;
        }
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(
                TlsAnalyzedProperty.QUIC_PORT_CONNECTION_MIGRATION_SUCCESSFUL,
                portConnectionMigrationSuccessful ? TestResults.TRUE : TestResults.FALSE);
        put(TlsAnalyzedProperty.QUIC_IPV6_ADDRESS, ipv6Address);
        if (ipv6HandshakeSuccessful) {
            put(TlsAnalyzedProperty.QUIC_IPV6_HANDSHAKE_DONE, TestResults.TRUE);
            put(
                    TlsAnalyzedProperty.QUIC_IPV6_CONNECTION_MIGRATION_SUCCESSFUL,
                    ipv6ConnectionMigrationSuccessful ? TestResults.TRUE : TestResults.FALSE);
        } else {
            put(TlsAnalyzedProperty.QUIC_IPV6_HANDSHAKE_DONE, TestResults.FALSE);
            put(
                    TlsAnalyzedProperty.QUIC_IPV6_CONNECTION_MIGRATION_SUCCESSFUL,
                    TestResults.COULD_NOT_TEST);
        }
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProtocolTypeTrueRequirement<>(ProtocolType.QUIC);
    }

    @Override
    public void adjustConfig(ServerReport report) {}
}
