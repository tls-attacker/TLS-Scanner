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
import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.QuicAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.QuicProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class QuicConnectionMigrationProbe extends QuicServerProbe {

    private boolean portConnectionMigrationSuccessful;
    private boolean portConnectionMigrationWithPathChallange;
    private String ipv6Address;
    private boolean ipv6HandshakeSuccessful;
    private boolean ipv6ConnectionMigrationSuccessful;
    private boolean ipv6ConnectionMigrationWithPathChallange;

    public QuicConnectionMigrationProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, QuicProbeType.CONNECTION_MIGRATION, configSelector);
        register(
                QuicAnalyzedProperty.PORT_CONNECTION_MIGRATION_SUCCESSFUL,
                QuicAnalyzedProperty.PORT_CONNECTION_MIGRATION_WITH_PATH_CHALLANGE,
                QuicAnalyzedProperty.IPV6_ADDRESS,
                QuicAnalyzedProperty.IPV6_HANDSHAKE_DONE,
                QuicAnalyzedProperty.IPV6_CONNECTION_MIGRATION_SUCCESSFUL,
                QuicAnalyzedProperty.IPV6_CONNECTION_MIGRATION_WITH_PATH_CHALLANGE);
    }

    @Override
    public void executeTest() {
        // Port Connection Migration
        Config config = configSelector.getTls13BaseConfig();
        config.setWorkflowTraceType(WorkflowTraceType.QUIC_PORT_CONNECTION_MIGRATION);
        config.setExpectHandshakeDoneQuicFrame(true);

        State state = new State(config);
        executeState(state);
        portConnectionMigrationSuccessful = state.getWorkflowTrace().executedAsPlanned();
        portConnectionMigrationWithPathChallange =
                WorkflowTraceResultUtil.didReceiveQuicFrame(
                        state.getWorkflowTrace(), QuicFrameType.PATH_CHALLENGE_FRAME);

        // IPV6 Handshake
        if (config.getDefaultClientConnection().getIpv6() != null) {
            config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HANDSHAKE);
            ipv6Address = config.getDefaultClientConnection().getIpv6();
            OutboundConnection ipv6Connection =
                    new OutboundConnection(config.getDefaultClientConnection());
            ipv6Connection.setUseIpv6(true);
            config.setDefaultClientConnection(ipv6Connection);

            state = new State(config);
            executeState(state);
            ipv6HandshakeSuccessful = state.getWorkflowTrace().executedAsPlanned();

            // IPV4 To IPV6 Connection Migration
            if (ipv6HandshakeSuccessful) {
                config.setWorkflowTraceType(WorkflowTraceType.QUIC_IPV6_CONNECTION_MIGRATION);
                state = new State(config);
                executeState(state);
                ipv6ConnectionMigrationSuccessful = state.getWorkflowTrace().executedAsPlanned();
                ipv6ConnectionMigrationWithPathChallange =
                        WorkflowTraceResultUtil.didReceiveQuicFrame(
                                state.getWorkflowTrace(), QuicFrameType.PATH_CHALLENGE_FRAME);
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
                QuicAnalyzedProperty.PORT_CONNECTION_MIGRATION_SUCCESSFUL,
                portConnectionMigrationSuccessful ? TestResults.TRUE : TestResults.FALSE);
        put(
                QuicAnalyzedProperty.PORT_CONNECTION_MIGRATION_WITH_PATH_CHALLANGE,
                portConnectionMigrationWithPathChallange ? TestResults.TRUE : TestResults.FALSE);
        put(QuicAnalyzedProperty.IPV6_ADDRESS, ipv6Address);
        if (ipv6HandshakeSuccessful) {
            put(QuicAnalyzedProperty.IPV6_HANDSHAKE_DONE, TestResults.TRUE);
            put(
                    QuicAnalyzedProperty.IPV6_CONNECTION_MIGRATION_SUCCESSFUL,
                    ipv6ConnectionMigrationSuccessful ? TestResults.TRUE : TestResults.FALSE);
            put(
                    QuicAnalyzedProperty.IPV6_CONNECTION_MIGRATION_WITH_PATH_CHALLANGE,
                    ipv6ConnectionMigrationWithPathChallange
                            ? TestResults.TRUE
                            : TestResults.FALSE);
        } else {
            put(QuicAnalyzedProperty.IPV6_HANDSHAKE_DONE, TestResults.FALSE);
            put(
                    QuicAnalyzedProperty.IPV6_CONNECTION_MIGRATION_SUCCESSFUL,
                    TestResults.COULD_NOT_TEST);
            put(
                    QuicAnalyzedProperty.IPV6_CONNECTION_MIGRATION_WITH_PATH_CHALLANGE,
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
