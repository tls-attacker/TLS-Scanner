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
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.QuicAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.QuicProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class QuicAntiDosLimitProbe extends QuicServerProbe {

    private TestResult holdsAntiDosLimit;

    public QuicAntiDosLimitProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, QuicProbeType.ANTI_DOS_LIMIT, configSelector);
        register(QuicAnalyzedProperty.HOLDS_ANTI_DOS_LIMIT);
    }

    @Override
    public void executeTest() {
        Config config = configSelector.getTls13BaseConfig();
        config.setExpectHandshakeDoneQuicFrame(false);

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        GenericReceiveAction receiveAction = new GenericReceiveAction();
        trace.addTlsAction(receiveAction);

        State state = new State(config, trace);
        executeState(state);

        if (WorkflowTraceResultUtil.getAllReceivedQuicPackets(trace).size() > 0) {
            if (WorkflowTraceResultUtil.didReceiveQuicPacket(trace, QuicPacketType.RETRY_PACKET)) {
                holdsAntiDosLimit = TestResults.TRUE;
                return;
            }
            int receivedBytes = 0;
            for (QuicPacket packet : WorkflowTraceResultUtil.getAllReceivedQuicPackets(trace)) {
                receivedBytes += packet.getPacketLength().getValue();
            }
            int sentBytes = 0;
            for (QuicPacket packet : WorkflowTraceResultUtil.getAllSentQuicPackets(trace)) {
                sentBytes += packet.getPacketLength().getValue();
            }
            holdsAntiDosLimit =
                    receivedBytes <= sentBytes * 3 ? TestResults.TRUE : TestResults.FALSE;
        } else {
            holdsAntiDosLimit = TestResults.ERROR_DURING_TEST;
        }
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(QuicAnalyzedProperty.HOLDS_ANTI_DOS_LIMIT, holdsAntiDosLimit);
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProtocolTypeTrueRequirement<>(ProtocolType.QUIC);
    }

    @Override
    public void adjustConfig(ServerReport report) {}
}
