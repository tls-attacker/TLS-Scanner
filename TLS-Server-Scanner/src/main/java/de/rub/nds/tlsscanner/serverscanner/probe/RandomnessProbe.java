/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.constants.ApplicationProtocol;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.LinkedList;
import java.util.List;

/**
 * A probe which samples random material from the target host using ServerHello randoms, SessionIDs
 * and IVs.
 */
public class RandomnessProbe extends TlsServerProbe {

    private ProtocolVersion bestVersion;
    private CipherSuite bestCipherSuite;
    private boolean supportsExtendedRandom;

    public RandomnessProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.RANDOMNESS, configSelector);
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProbeRequirement<>(
                TlsProbeType.CIPHER_SUITE, TlsProbeType.PROTOCOL_VERSION, TlsProbeType.EXTENSIONS);
    }

    @Override
    protected void executeTest() {
        collectData(configSelector.getScannerConfig().getAdditionalRandomnessHandshakes());
    }

    @Override
    public void adjustConfig(ServerReport report) {
        chooseBestCipherAndVersion(report);
        supportsExtendedRandom =
                report.getSupportedExtensions().contains(ExtensionType.EXTENDED_RANDOM);
    }

    private void chooseBestCipherAndVersion(ServerReport report) {
        int bestScore = 0;
        List<VersionSuiteListPair> versionSuitePairs =
                report.getListResult(
                                TlsAnalyzedProperty.VERSION_SUITE_PAIRS, VersionSuiteListPair.class)
                        .getList();
        for (VersionSuiteListPair pair : versionSuitePairs) {
            for (CipherSuite suite : pair.getCipherSuiteList()) {
                int score = 0;
                if (!pair.getVersion().isTLS13()) {
                    score += 64; // random + session id
                    if (suite.isCBC()
                                    && (pair.getVersion() == ProtocolVersion.TLS12
                                            || pair.getVersion() == ProtocolVersion.TLS11)
                            || pair.getVersion() == ProtocolVersion.DTLS12
                            || pair.getVersion() == ProtocolVersion.DTLS10) {
                        score += AlgorithmResolver.getCipher(suite).getBlocksize();
                    }
                } else {
                    score += 28;
                }
                if (score > bestScore) {
                    bestScore = score;
                    bestCipherSuite = suite;
                    bestVersion = pair.getVersion();
                }
            }
        }
    }

    private void collectData(int numberOfHandshakes) {
        List<State> stateList = new LinkedList<>();
        for (int i = 0; i < numberOfHandshakes; i++) {
            Config config;
            if (bestVersion.isTLS13()) {
                config = configSelector.getTls13BaseConfig();
            } else {
                config = configSelector.getBaseConfig();
            }
            config.setHighestProtocolVersion(bestVersion);
            config.setDefaultClientSupportedCipherSuites(bestCipherSuite);
            if (supportsExtendedRandom) {
                config.setAddExtendedRandomExtension(true);
            }
            configSelector.repairConfig(config);
            WorkflowTrace workflowTrace =
                    new WorkflowConfigurationFactory(config)
                            .createWorkflowTrace(
                                    WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);

            ApplicationProtocol applicationProtocol =
                    configSelector.getScannerConfig().getApplicationProtocol();
            StackConfiguration expLayerConfiguration =
                    applicationProtocol.getExpectedStackConfiguration();
            if (expLayerConfiguration != null) {
                config.setDefaultLayerConfiguration(expLayerConfiguration);
            }
            try {
                workflowTrace.addTlsActions(applicationProtocol.createDummyActions(config));
            } catch (UnsupportedOperationException e) {
                // TODO: Add application specific app data to provoke data transmission
                LOGGER.warn(
                        "No application specific actions for {} available; could not provoke data transmission.",
                        applicationProtocol);
            }

            State state = new State(config, workflowTrace);
            stateList.add(state);
        }
        executeState(stateList);
    }

    @Override
    protected void mergeData(ServerReport report) {
        // Nothing to do here - all data analysis is done in the after probe
    }
}
