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
import de.rub.nds.tlsattacker.core.quic.constants.QuicVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.QuicProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.quic.QuicVersionResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import de.rub.nds.tlsscanner.serverscanner.selector.DefaultConfigProfile;
import java.util.List;
import java.util.stream.Collectors;

public class QuicVersionProbe
        extends QuicServerProbe<ConfigSelector, ServerReport, QuicVersionResult> {

    public QuicVersionProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, QuicProbeType.SUPPORTED_VERSION, configSelector);
    }

    @Override
    public QuicVersionResult executeTest() {
        // use basic config to avoid sending client hello in multiple packets which would lead to
        // the server sending multiple version negotiation packets
        Config config =
                configSelector.getConfigForProfile(
                        ConfigSelector.TLS13_CONFIG, DefaultConfigProfile.CLEAN_TLS_13);
        config.setExpectHandshakeDoneQuicFrame(false);
        config.setWorkflowTraceType(WorkflowTraceType.QUIC_VERSION_NEGOTIATION);
        config.setQuicVersion(QuicVersion.NEGOTIATION_VERSION.getByteValue());
        config.setFinishWithCloseNotify(false);
        State state = new State(config);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            LOGGER.info(
                    "Supported Quic Versions: "
                            + state.getContext().getQuicContext().getSupportedVersions().stream()
                                    .map(QuicVersion::getVersionNameFromBytes)
                                    .collect(Collectors.joining(", ")));
            return new QuicVersionResult(
                    state.getContext().getQuicContext().getSupportedVersions());
        } else {
            return new QuicVersionResult(List.of());
        }
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return true;
    }

    @Override
    public QuicVersionResult getCouldNotExecuteResult() {
        return null;
    }

    @Override
    public void adjustConfig(ServerReport report) {}
}
