/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.quic.constants.QuicVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.QuicProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.QuicVersionResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.List;
import java.util.stream.Collectors;

public class QuicVersionProbe
        extends QuicServerProbe<ConfigSelector, ServerReport, QuicVersionResult<ServerReport>> {

    public QuicVersionProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, QuicProbeType.SUPPORTED_VERSION, configSelector);
    }

    @Override
    public QuicVersionResult<ServerReport> executeTest() {
        Config config = configSelector.getTls13BaseConfig();
        config.setExpectHandshakeDoneQuicFrame(false);
        config.setWorkflowTraceType(WorkflowTraceType.QUIC_VERSION_NEGOTIATION);
        config.setQuicVersion(QuicVersion.NEGOTIATION_VERSION.getByteValue());
        State state = new State(config);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            LOGGER.info(
                    "Supported Quic Versions: "
                            + state.getContext().getQuicContext().getSupportedVersions().stream()
                                    .map(QuicVersion::getVersionNameFromBytes)
                                    .collect(Collectors.joining(", ")));
            return new QuicVersionResult<>(
                    QuicProbeType.SUPPORTED_VERSION,
                    state.getContext().getQuicContext().getSupportedVersions());
        } else {
            return new QuicVersionResult<>(QuicProbeType.SUPPORTED_VERSION, List.of());
        }
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return true;
    }

    @Override
    public QuicVersionResult<ServerReport> getCouldNotExecuteResult() {
        return null;
    }

    @Override
    public void adjustConfig(ServerReport report) {}
}
