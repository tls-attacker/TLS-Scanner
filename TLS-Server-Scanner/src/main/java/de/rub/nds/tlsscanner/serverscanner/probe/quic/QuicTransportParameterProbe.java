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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameters;
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

public class QuicTransportParameterProbe extends QuicServerProbe {

    private TestResults sendsTransportParameters;
    private QuicTransportParameters transportParameters;

    public QuicTransportParameterProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, QuicProbeType.TRANSPORT_PARAMETERS, configSelector);
        register(
                QuicAnalyzedProperty.SENDS_TRANSPORT_PARAMETERS,
                QuicAnalyzedProperty.TRANSPORT_PARAMETERS);
    }

    @Override
    public void executeTest() {
        Config config = configSelector.getTls13BaseConfig();
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);

        State state = new State(config);
        executeState(state);

        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.ENCRYPTED_EXTENSIONS)) {
            if (state.getTlsContext()
                    .getNegotiatedExtensionSet()
                    .contains(ExtensionType.QUIC_TRANSPORT_PARAMETERS)) {
                sendsTransportParameters = TestResults.TRUE;
                transportParameters =
                        state.getContext().getQuicContext().getReceivedTransportParameters();
            } else {
                sendsTransportParameters = TestResults.FALSE;
                transportParameters = new QuicTransportParameters();
            }
        } else {
            sendsTransportParameters = TestResults.ERROR_DURING_TEST;
            transportParameters = null;
        }
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(QuicAnalyzedProperty.SENDS_TRANSPORT_PARAMETERS, sendsTransportParameters);
        put(QuicAnalyzedProperty.TRANSPORT_PARAMETERS, transportParameters);
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProtocolTypeTrueRequirement<>(ProtocolType.QUIC);
    }

    @Override
    public void adjustConfig(ServerReport report) {}
}
