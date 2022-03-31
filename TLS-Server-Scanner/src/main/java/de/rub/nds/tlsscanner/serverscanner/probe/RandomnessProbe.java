/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.constants.ApplicationProtocol;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.RandomnessResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

import java.util.LinkedList;
import java.util.List;

/**
 * A probe which samples random material from the target host using ServerHello randoms, SessionIDs and IVs.
 */
public class RandomnessProbe extends TlsProbe {

    private ProtocolVersion bestVersion;
    private CipherSuite bestCipherSuite;
    private boolean supportsExtendedRandom;

    public RandomnessProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.RANDOMNESS, configSelector);
    }

    @Override
    public ProbeResult executeTest() {
        collectData(getScannerConfig().getAdditionalRandomnessHandshakes());
        return new RandomnessResult();
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.isProbeAlreadyExecuted(ProbeType.CIPHER_SUITE)
            && report.isProbeAlreadyExecuted(ProbeType.PROTOCOL_VERSION)
            && report.isProbeAlreadyExecuted(ProbeType.EXTENSIONS);
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new RandomnessResult();
    }

    @Override
    public void adjustConfig(SiteReport report) {
        chooseBestCipherAndVersion(report);
        supportsExtendedRandom = report.getSupportedExtensions().contains(ExtensionType.EXTENDED_RANDOM);
    }

    private void chooseBestCipherAndVersion(SiteReport report) {
        int bestScore = 0;
        List<VersionSuiteListPair> versionSuitePairs = report.getVersionSuitePairs();
        for (VersionSuiteListPair pair : versionSuitePairs) {
            for (CipherSuite suite : pair.getCipherSuiteList()) {
                int score = 0;
                if (!pair.getVersion().isTLS13()) {
                    score += 64; // random + session id
                    if (suite.isCBC()
                        && (pair.getVersion() == ProtocolVersion.TLS12 || pair.getVersion() == ProtocolVersion.TLS11)
                        || pair.getVersion() == ProtocolVersion.DTLS12 || pair.getVersion() == ProtocolVersion.DTLS10) {
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
                config = getConfigSelector().getTls13BaseConfig();
            } else {
                config = getConfigSelector().getBaseConfig();
            }
            config.setHighestProtocolVersion(bestVersion);
            config.setDefaultClientSupportedCipherSuites(bestCipherSuite);
            if (supportsExtendedRandom) {
                config.setAddExtendedRandomExtension(true);
            }
            getConfigSelector().repairConfig(config);
            WorkflowTrace workflowTrace = new WorkflowConfigurationFactory(config)
                .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);
            if (getScannerConfig().getApplicationProtocol() == ApplicationProtocol.HTTP) {
                config.setHttpsParsingEnabled(true);
                workflowTrace.addTlsAction(new SendAction(new HttpsRequestMessage(config)));
                workflowTrace.addTlsAction(new ReceiveAction(new HttpsResponseMessage(config)));
            } else {
                // TODO: Add application specific app data to provoke data transmission
            }
            State state = new State(config, workflowTrace);
            stateList.add(state);
        }
        executeState(stateList);
    }
}
