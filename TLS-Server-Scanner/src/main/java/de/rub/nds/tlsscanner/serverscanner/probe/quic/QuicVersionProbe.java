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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.quic.constants.QuicVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.QuicAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.QuicProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import de.rub.nds.tlsscanner.serverscanner.selector.DefaultConfigProfile;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class QuicVersionProbe extends QuicServerProbe {

    private List<byte[]> supportedVersions;

    public QuicVersionProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, QuicProbeType.SUPPORTED_VERSIONS, configSelector);
        this.supportedVersions = new ArrayList<>();
    }

    @Override
    public void executeTest() {
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
        supportedVersions =
                state.getWorkflowTrace().executedAsPlanned()
                        ? state.getContext().getQuicContext().getSupportedVersions()
                        : List.of();
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(
                QuicAnalyzedProperty.VERSIONS,
                supportedVersions.stream()
                        .map(
                                versionBytes ->
                                        new Entry(
                                                QuicVersion.getVersionNameFromBytes(versionBytes),
                                                versionBytes))
                        .collect(Collectors.toList()));
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProtocolTypeTrueRequirement<>(ProtocolType.QUIC);
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    public class Entry {
        private String versionName;
        private byte[] versionBytes;

        public Entry(String versionName, byte[] versionBytes) {
            this.versionName = versionName;
            this.versionBytes = versionBytes;
        }

        public String getVersionName() {
            return versionName;
        }

        public void setVersionName(String versionName) {
            this.versionName = versionName;
        }

        public byte[] getVersionBytes() {
            return versionBytes;
        }

        public void setVersionBytes(byte[] versionBytes) {
            this.versionBytes = versionBytes;
        }
    }
}
