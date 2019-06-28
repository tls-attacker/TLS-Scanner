/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.result.CiphersuiteProbeResult;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class CiphersuiteProbe extends TlsProbe {

    private final List<ProtocolVersion> protocolVersions;

    public CiphersuiteProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.CIPHERSUITE, config, 0);
        protocolVersions = new LinkedList<>();
        protocolVersions.add(ProtocolVersion.TLS10);
        protocolVersions.add(ProtocolVersion.TLS11);
        protocolVersions.add(ProtocolVersion.TLS12);
    }

    @Override
    public ProbeResult executeTest() {
        List<VersionSuiteListPair> pairLists = new LinkedList<>();
        for (ProtocolVersion version : protocolVersions) {
            LOGGER.debug("Testing:" + version.name());
            List<CipherSuite> toTestList = new LinkedList<>();
            toTestList.addAll(Arrays.asList(CipherSuite.values()));
            toTestList.remove(CipherSuite.TLS_FALLBACK_SCSV);
            toTestList.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
            List<CipherSuite> versionSupportedSuites = getSupportedCipherSuitesWithIntolerance(toTestList, version);
            if (versionSupportedSuites.isEmpty()) {
                versionSupportedSuites = getSupportedCipherSuitesWithIntolerance(version);
            }
            if (versionSupportedSuites.size() > 0) {
                pairLists.add(new VersionSuiteListPair(version, versionSupportedSuites));
            }

        }

        return new CiphersuiteProbeResult(pairLists);

    }

    public List<CipherSuite> getSupportedCipherSuitesWithIntolerance(ProtocolVersion version) {
        return getSupportedCipherSuitesWithIntolerance(new ArrayList<>(CipherSuite.getImplemented()), version);
    }

    public List<CipherSuite> getSupportedCipherSuitesWithIntolerance(List<CipherSuite> toTestList, ProtocolVersion version) {
        List<CipherSuite> listWeSupport = new LinkedList<>(toTestList);
        List<CipherSuite> supported = new LinkedList<>();

        boolean supportsMore = false;
        do {
            Config config = getScannerConfig().createConfig();
            config.setDefaultClientSupportedCiphersuites(listWeSupport);
            config.setHighestProtocolVersion(version);
            config.setEnforceSettings(true);
            config.setAddServerNameIndicationExtension(true);
            boolean containsEc = false;
            for (CipherSuite suite : config.getDefaultClientSupportedCiphersuites()) {
                KeyExchangeAlgorithm keyExchangeAlgorithm = AlgorithmResolver.getKeyExchangeAlgorithm(suite);
                if (keyExchangeAlgorithm != null && keyExchangeAlgorithm.name().toUpperCase().contains("EC")) {
                    containsEc = true;
                    break;
                }
            }
            config.setAddEllipticCurveExtension(containsEc);
            config.setAddECPointFormatExtension(containsEc);
            config.setAddSignatureAndHashAlgorithmsExtension(true);
            config.setAddRenegotiationInfoExtension(true);
            config.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
            config.setQuickReceive(true);
            config.setEarlyStop(true);
            config.setStopActionsAfterFatal(true);
            List<NamedGroup> namedGroup = new LinkedList<>();
            namedGroup.addAll(Arrays.asList(NamedGroup.values()));
            config.setDefaultClientNamedGroups(namedGroup);
            State state = new State(config);
            executeState(state);
            if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
                if (state.getTlsContext().getSelectedProtocolVersion() != version) {
                    LOGGER.debug("Server does not support " + version);
                    return new LinkedList<>();
                }
                LOGGER.debug("Server chose " + state.getTlsContext().getSelectedCipherSuite().name());
                if (listWeSupport.contains(state.getTlsContext().getSelectedCipherSuite())) {
                    supportsMore = true;
                    supported.add(state.getTlsContext().getSelectedCipherSuite());
                    listWeSupport.remove(state.getTlsContext().getSelectedCipherSuite());
                } else {
                    supportsMore = false;
                    LOGGER.warn("Server chose not proposed Ciphersuite");
                }
            } else {
                supportsMore = false;
                LOGGER.debug("Server did not send ServerHello");
                LOGGER.debug(state.getWorkflowTrace().toString());
                if (state.getTlsContext().isReceivedFatalAlert()) {
                    LOGGER.debug("Received Fatal Alert");
                    AlertMessage alert = (AlertMessage) WorkflowTraceUtil.getFirstReceivedMessage(ProtocolMessageType.ALERT, state.getWorkflowTrace());
                    LOGGER.debug("Type:" + alert.toString());

                }
            }
        } while (supportsMore);
        return supported;
    }

    @Override
    public boolean shouldBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getNotExecutedResult() {
        return null;
    }
}
