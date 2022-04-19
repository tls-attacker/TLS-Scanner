/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ApplicationProtocol;
import de.rub.nds.tlsscanner.serverscanner.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.LinkedList;
import java.util.List;

/**
 * A probe which samples random material from the target host using ServerHello randoms, SessionIDs and IVs.
 */
public class RandomnessProbe extends TlsProbe<ServerScannerConfig, ServerReport> {

    private ProtocolVersion bestVersion;
    private CipherSuite bestCipherSuite;
    private boolean supportsExtendedRandom;

    public RandomnessProbe(ServerScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.RANDOMNESS, config);
    }

    @Override
    public void executeTest() {
        collectData(scannerConfig.getAdditionalRandomnessHandshakes());
    }

    @Override
    protected Requirement getRequirements(ServerReport report) {
        return new ProbeRequirement(report).requireProbeTypes(TlsProbeType.CIPHER_SUITE, TlsProbeType.PROTOCOL_VERSION,
            TlsProbeType.EXTENSIONS);
    }

    @Override
    public RandomnessProbe getCouldNotExecuteResult() {
        return this;
    }

    @Override
    public void adjustConfig(ServerReport report) {
        chooseBestCipherAndVersion(report);
        if (report.getSupportedExtensions().contains(ExtensionType.EXTENDED_RANDOM)) {
            supportsExtendedRandom = true;
        } else {
            supportsExtendedRandom = false;
        }
    }

    private void chooseBestCipherAndVersion(ServerReport report) {
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

    private Config generateTls13BaseConfig() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(bestCipherSuite);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS13);
        tlsConfig.setSupportedVersions(ProtocolVersion.TLS13);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setDefaultClientNamedGroups(NamedGroup.getImplemented());
        tlsConfig.setAddECPointFormatExtension(false);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddSupportedVersionsExtension(true);
        tlsConfig.setAddKeyShareExtension(true);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setUseFreshRandom(true);

        List<SignatureAndHashAlgorithm> algos = SignatureAndHashAlgorithm.getTls13SignatureAndHashAlgorithms();
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(algos);

        return tlsConfig;
    }

    private Config generateBaseConfig() {

        Config config = getScannerConfig().createConfig();
        config.setHighestProtocolVersion(bestVersion);
        config.setDefaultClientSupportedCipherSuites(bestCipherSuite);
        config.setAddServerNameIndicationExtension(false);
        if (bestCipherSuite.name().contains("ECDH")) {
            config.setAddEllipticCurveExtension(true);
            config.setAddECPointFormatExtension(true);
        }
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddRenegotiationInfoExtension(false);
        config.setUseFreshRandom(true);
        config.setStopReceivingAfterFatal(true);
        config.setAddServerNameIndicationExtension(true);
        config.setDefaultClientSessionId(new byte[0]);
        config.setStopActionsAfterFatal(true);
        config.setStopActionsAfterIOException(true);
        config.setStopActionsAfterWarning(true);
        config.setQuickReceive(true);
        config.setEarlyStop(true);
        return config;
    }

    private void collectData(int numberOfHandshakes) {
        List<State> stateList = new LinkedList<>();
        for (int i = 0; i < numberOfHandshakes; i++) {
            Config config;
            if (bestVersion.isTLS13()) {
                config = generateTls13BaseConfig();
            } else {
                config = generateBaseConfig();
            }
            if (supportsExtendedRandom) {
                config.setAddExtendedRandomExtension(true);
            }
            WorkflowTrace workflowTrace = new WorkflowConfigurationFactory(config)
                .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);
            if (scannerConfig.getApplicationProtocol() == ApplicationProtocol.HTTP) {
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

    @Override
    protected void mergeData(ServerReport report) {
        // Nothing to do here - all data analysis is done in the after probe
    }
}
