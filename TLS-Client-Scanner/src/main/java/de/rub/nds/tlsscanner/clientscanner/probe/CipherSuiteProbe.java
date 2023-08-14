/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.ciphersuite.CipherSuiteEvaluationHelper;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import java.util.LinkedList;
import java.util.List;

public class CipherSuiteProbe extends TlsClientProbe {

    private final CipherSuiteEvaluationHelper evaluationHelper;

    public CipherSuiteProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
        super(executor, TlsProbeType.CIPHER_SUITE, scannerConfig);
        evaluationHelper = new CipherSuiteEvaluationHelper(new LinkedList<>());
        register(CipherSuiteEvaluationHelper.getProperties());
    }

    @Override
    protected void executeTest() {
        evaluationHelper.setPairLists(new LinkedList<>());
        List<State> statesToExecute = new LinkedList<>();
        for (ProtocolVersion version : evaluationHelper.getProtocolVersions()) {
            evaluationHelper
                    .getPairLists()
                    .add(new VersionSuiteListPair(version, new LinkedList<>()));
            LOGGER.debug("Testing cipher suites for version {}", version);

            List<CipherSuite> toTestList =
                    evaluationHelper.getToTestCipherSuitesByVersion(version, scannerConfig);

            while (!toTestList.isEmpty()) {
                Config config;
                if (version.isTLS13()) {
                    config = getTls13Config();
                } else {
                    config = getBaseConfig();
                }
                config.setHighestProtocolVersion(version);
                config.setDefaultSelectedProtocolVersion(version);
                config.setEnforceSettings(true);
                CipherSuite currentSuite = toTestList.get(0);
                config.setDefaultServerSupportedCipherSuites(currentSuite);
                config.setDefaultSelectedCipherSuite(currentSuite);
                WorkflowTrace trace =
                        new WorkflowConfigurationFactory(config)
                                .createWorkflowTrace(
                                        WorkflowTraceType.HELLO, RunningModeType.SERVER);
                trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

                State state = new State(config, trace);
                statesToExecute.add(state);

                toTestList.remove(currentSuite);
            }
        }
        executeState(statesToExecute);
        for (State executedState : statesToExecute) {
            if (executedState.getWorkflowTrace().executedAsPlanned()
                    && executedState.getTlsContext().getSelectedCipherSuite()
                            == executedState.getConfig().getDefaultSelectedCipherSuite()) {
                evaluationHelper.getPairLists().stream()
                        .filter(
                                pair ->
                                        pair.getVersion()
                                                == executedState
                                                        .getConfig()
                                                        .getDefaultSelectedProtocolVersion())
                        .findAny()
                        .orElseThrow()
                        .getCipherSuiteList()
                        .add(executedState.getConfig().getDefaultSelectedCipherSuite());
            }
        }
    }

    private Config getBaseConfig() {
        Config config = scannerConfig.createConfig();
        config.setStopReceivingAfterFatal(true);
        config.setStopActionsAfterFatal(true);
        config.setStopActionsAfterIOException(true);
        config.setStopTraceAfterUnexpected(true);
        config.setStopActionsAfterWarning(true);
        return config;
    }

    private Config getTls13Config() {
        Config config = getBaseConfig();
        config.setSupportedVersions(ProtocolVersion.TLS13);
        config.setAddECPointFormatExtension(false);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);
        return config;
    }

    @Override
    public void adjustConfig(ClientReport report) {
        evaluationHelper.configureVersions(report);
    }

    @Override
    public Requirement<ClientReport> getRequirements() {
        return new ProbeRequirement<>(TlsProbeType.PROTOCOL_VERSION);
    }

    @Override
    protected void mergeData(ClientReport report) {
        evaluationHelper.mergeData(report, this);
    }
}
