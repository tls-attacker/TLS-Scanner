/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.quic;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.constants.QuicVersion;
import de.rub.nds.tlsattacker.core.quic.packet.InitialPacket;
import de.rub.nds.tlsattacker.core.quic.packet.VersionNegotiationPacket;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.QuicAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.QuicProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.List;

public class QuicVersionProbe extends QuicServerProbe {

    private TestResults sendsVersionNegotiationPacket;
    private List<byte[]> supportedVersions;

    public QuicVersionProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, QuicProbeType.SUPPORTED_VERSIONS, configSelector);
        register(
                QuicAnalyzedProperty.SENDS_VERSIONS_NEGOTIATION_PACKET,
                QuicAnalyzedProperty.VERSIONS);
    }

    @Override
    public void executeTest() {
        Config config = configSelector.getTls13BaseConfig();

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        SendAction sendAction = new SendAction(new ClientHelloMessage());
        InitialPacket packet = new InitialPacket();
        packet.setQuicVersion(Modifiable.explicit(QuicVersion.NEGOTIATION_VERSION.getByteValue()));
        sendAction.setConfiguredQuicPackets(packet);
        trace.addTlsAction(sendAction);
        trace.addTlsAction(new ReceiveAction(new VersionNegotiationPacket()));

        State state = new State(config, trace);
        executeState(state);

        if (WorkflowTraceResultUtil.didReceiveQuicPacket(
                state.getWorkflowTrace(), QuicPacketType.VERSION_NEGOTIATION)) {
            sendsVersionNegotiationPacket = TestResults.TRUE;
            supportedVersions = state.getContext().getQuicContext().getSupportedVersions();
        } else {
            sendsVersionNegotiationPacket = TestResults.FALSE;
            supportedVersions = null;
        }
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(QuicAnalyzedProperty.SENDS_VERSIONS_NEGOTIATION_PACKET, sendsVersionNegotiationPacket);
        put(QuicAnalyzedProperty.VERSIONS, supportedVersions);
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProtocolTypeTrueRequirement<>(ProtocolType.QUIC);
    }

    @Override
    public void adjustConfig(ServerReport report) {}
}
