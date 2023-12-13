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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.ciphersuite.CipherSuiteEvaluationHelper;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class CipherSuiteProbe extends TlsServerProbe {

    private final CipherSuiteEvaluationHelper evaluationHelper;

    public CipherSuiteProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.CIPHER_SUITE, configSelector);
        evaluationHelper = new CipherSuiteEvaluationHelper(new LinkedList<>());
        register(CipherSuiteEvaluationHelper.getProperties());
    }

    @Override
    protected void executeTest() {
        evaluationHelper.setPairLists(new LinkedList<>());
        for (ProtocolVersion version : evaluationHelper.getProtocolVersions()) {
            LOGGER.debug("Testing:" + version.name());
            if (version.isTLS13()) {
                evaluationHelper
                        .getPairLists()
                        .add(new VersionSuiteListPair(version, getSupportedTls13CipherSuites()));
            } else {
                List<CipherSuite> toTestList =
                        new LinkedList<>(Arrays.asList(CipherSuite.values()));
                List<CipherSuite> versionSupportedSuites =
                        getSupportedCipherSuites(toTestList, version);
                if (versionSupportedSuites.isEmpty()) {
                    versionSupportedSuites =
                            getSupportedCipherSuites(CipherSuite.getImplemented(), version);
                }
                if (versionSupportedSuites.size() > 0) {
                    evaluationHelper
                            .getPairLists()
                            .add(new VersionSuiteListPair(version, versionSupportedSuites));
                }
            }
        }
    }

    private List<CipherSuite> getCipherSuitesForVersion(
            List<CipherSuite> baseList, ProtocolVersion version) {
        List<CipherSuite> applicableCipherSuites =
                baseList.stream()
                        .filter(cipherSuite -> cipherSuite.isSupportedInProtocol(version))
                        .collect(Collectors.toList());
        applicableCipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        applicableCipherSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        return applicableCipherSuites;
    }

    private List<CipherSuite> getSupportedTls13CipherSuites() {
        CipherSuite selectedSuite = null;
        List<CipherSuite> toTestList = CipherSuite.getTls13CipherSuites();
        List<CipherSuite> supportedSuits = new LinkedList<>();
        do {
            selectedSuite = getSelectedTls13CipherSuite(toTestList);
            if (selectedSuite != null) {
                if (!toTestList.contains(selectedSuite)) {
                    LOGGER.warn("Server chose a CipherSuite we did not propose!");
                    // TODO write to site report
                    break;
                }
                supportedSuits.add(selectedSuite);
                toTestList.remove(selectedSuite);
            }
        } while (selectedSuite != null && !toTestList.isEmpty());
        return supportedSuits;
    }

    private CipherSuite getSelectedTls13CipherSuite(List<CipherSuite> toTestList) {
        Config tlsConfig = configSelector.getTls13BaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setDefaultClientSupportedCipherSuites(toTestList);
        configSelector.repairConfig(tlsConfig);
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO)) {
            return state.getTlsContext().getSelectedCipherSuite();
        } else {
            LOGGER.debug("Did not receive ServerHello Message");
            LOGGER.debug(state.getWorkflowTrace().toString());
            return null;
        }
    }

    public List<CipherSuite> getSupportedCipherSuites(
            List<CipherSuite> baseList, ProtocolVersion version) {
        List<CipherSuite> listWeSupport = getCipherSuitesForVersion(baseList, version);
        List<CipherSuite> supported = new LinkedList<>();

        boolean supportsMore = false;
        do {
            Config config = configSelector.getBaseConfig();
            config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
            config.setDefaultClientSupportedCipherSuites(listWeSupport);
            config.setDefaultSelectedProtocolVersion(version);
            config.setHighestProtocolVersion(version);
            config.setEnforceSettings(true);
            configSelector.repairConfig(config);
            State state = new State(config);
            executeState(state);
            if (WorkflowTraceResultUtil.didReceiveMessage(
                    state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO)) {
                if (state.getTlsContext().getSelectedProtocolVersion() != version) {
                    LOGGER.debug("Server does not support " + version);
                    return new LinkedList<>();
                }
                LOGGER.debug(
                        "Server chose " + state.getTlsContext().getSelectedCipherSuite().name());
                if (listWeSupport.contains(state.getTlsContext().getSelectedCipherSuite())) {
                    supportsMore = true;
                    supported.add(state.getTlsContext().getSelectedCipherSuite());
                    listWeSupport.remove(state.getTlsContext().getSelectedCipherSuite());
                } else {
                    supportsMore = false;
                    LOGGER.warn("Server chose not proposed cipher suite");
                }
            } else {
                supportsMore = false;
                LOGGER.debug("Server did not send ServerHello");
                LOGGER.debug(state.getWorkflowTrace().toString());
                if (state.getTlsContext().isReceivedFatalAlert()) {
                    LOGGER.debug("Received Fatal Alert");
                    AlertMessage alert =
                            (AlertMessage)
                                    WorkflowTraceResultUtil.getFirstReceivedMessage(
                                            state.getWorkflowTrace(), ProtocolMessageType.ALERT);
                    LOGGER.debug("Type:" + alert.toString());
                }
            }
        } while (supportsMore);
        return supported;
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProbeRequirement<>(TlsProbeType.PROTOCOL_VERSION);
    }

    @Override
    public void adjustConfig(ServerReport report) {
        evaluationHelper.configureVersions(report);
    }

    @Override
    protected void mergeData(ServerReport report) {
        evaluationHelper.mergeData(report, this);
    }
}
