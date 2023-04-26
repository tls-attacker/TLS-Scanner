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
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameters;
import de.rub.nds.tlsattacker.core.quic.constants.QuicVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.QuicProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.quic.QuicTransportParameterResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class QuicTransportParameterProbe
        extends QuicServerProbe<ConfigSelector, ServerReport, QuicTransportParameterResult> {

    public QuicTransportParameterProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, QuicProbeType.TRANSPORT_PARAMETERS, configSelector);
    }

    @Override
    public QuicTransportParameterResult executeTest() {
        Config config = configSelector.getTls13BaseConfig();
        config.setExpectHandshakeDoneQuicFrame(true);
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HANDSHAKE);
        config.setQuicVersion(QuicVersion.VERSION_1.getByteValue());
        State state = new State(config);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            QuicTransportParameters transportParameters =
                    state.getContext().getQuicContext().getReceivedTransportParameters();
            return new QuicTransportParameterResult(transportParameters);
        } else {
            return new QuicTransportParameterResult(null);
        }
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return true;
    }

    @Override
    public QuicTransportParameterResult getCouldNotExecuteResult() {
        return null;
    }

    @Override
    public void adjustConfig(ServerReport report) {}
}
