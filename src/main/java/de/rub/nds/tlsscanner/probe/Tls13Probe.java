/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.Tls13Result;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class Tls13Probe extends TlsProbe {

    public Tls13Probe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.TLS13, scannerConfig, 0);
    }

    private List<CipherSuite> getSupportedCiphersuites() {
        CipherSuite selectedSuite = null;
        List<CipherSuite> toTestList = new LinkedList<>();
        List<CipherSuite> supportedSuits = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.values()) {
            if (suite.isTLS13()) {
                toTestList.add(suite);
            }
        }
        do {
            selectedSuite = getSelectedCiphersuite(toTestList);

            if (selectedSuite != null) {
                if (!toTestList.contains(selectedSuite)) {
                    LOGGER.warn("Server chose a CipherSuite we did not propose!");
                    // TODO write to sitereport
                    break;
                }
                supportedSuits.add(selectedSuite);
                toTestList.remove(selectedSuite);
            }
        } while (selectedSuite != null && !toTestList.isEmpty());
        return supportedSuits;
    }

    private CipherSuite getSelectedCiphersuite(List<CipherSuite> toTestList) {
        Config tlsConfig = getCommonConfig(WorkflowTraceType.SHORT_HELLO, ProtocolVersion.TLS13, getTls13ProtocolVersions(), toTestList, getTls13Groups());
        State state = new State(tlsConfig);
        setupKeyShares(state.getWorkflowTrace());
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            // ServerHelloMessage message = (ServerHelloMessage)
            // WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO,
            // state.getWorkflowTrace());
            return state.getTlsContext().getSelectedCipherSuite();
        } else if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.HELLO_RETRY_REQUEST,
                state.getWorkflowTrace())) {
            return state.getTlsContext().getSelectedCipherSuite();
        } else {
            LOGGER.debug("Did not receive ServerHello Message");
            LOGGER.debug(state.getWorkflowTrace().toString());
            return null;
        }
    }

    private List<NamedGroup> getSupportedGroups() {
        List<NamedGroup> tempSupportedGroups = null;
        List<NamedGroup> toTestList = new LinkedList<>();
        List<NamedGroup> supportedGroups = new LinkedList<>();
        for (NamedGroup group : NamedGroup.values()) {
            if (group.isTls13()) {
                toTestList.add(group);
            }
        }
        do {
            tempSupportedGroups = getSupportedGroups(toTestList);
            if (tempSupportedGroups != null) {
                for (NamedGroup group : tempSupportedGroups) {
                    if (!toTestList.contains(group)) {
                        LOGGER.warn("Server chose a group we did not offer");
                        // TODO add to site report
                        return supportedGroups;
                    }
                }
                supportedGroups.addAll(tempSupportedGroups);
                for (NamedGroup group : tempSupportedGroups) {
                    toTestList.remove(group);
                }
            }
        } while (tempSupportedGroups != null && !toTestList.isEmpty());
        return supportedGroups;
    }

    public List<NamedGroup> getSupportedGroups(List<NamedGroup> group) {
        Config tlsConfig = getCommonConfig(WorkflowTraceType.SHORT_HELLO, ProtocolVersion.TLS13, getTls13ProtocolVersions(), getTls13Suite(), group);
        State state = new State(tlsConfig);
        setupKeyShares(state.getWorkflowTrace());
        executeState(state);
        if (state.getTlsContext().isExtensionNegotiated(ExtensionType.ELLIPTIC_CURVES)) {
            return state.getTlsContext().getServerNamedGroupsList();
        } else if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            // ServerHelloMessage message = (ServerHelloMessage)
            // WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO,
            // state.getWorkflowTrace());
            return new ArrayList(Arrays.asList(state.getTlsContext().getSelectedGroup()));
        } else if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.HELLO_RETRY_REQUEST,
                state.getWorkflowTrace())) {
            return new ArrayList(Arrays.asList(state.getTlsContext().getSelectedGroup()));
        } else {
            LOGGER.debug("Did not receive ServerHello Message");
            LOGGER.debug(state.getWorkflowTrace().toString());
            return null;
        }
    }

    private boolean isTls13Supported(ProtocolVersion toTest) {
        Config tlsConfig = getCommonConfig(WorkflowTraceType.SHORT_HELLO, toTest, getTls13Suite(), getTls13Groups());
        State state = new State(tlsConfig);
        setupKeyShares(state.getWorkflowTrace());
        executeState(state);
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            LOGGER.debug("Did not receive ServerHello Message");
            LOGGER.debug(state.getWorkflowTrace().toString());
            return false;
        } else {
            LOGGER.debug("Received ServerHelloMessage");
            LOGGER.debug(state.getWorkflowTrace().toString());
            LOGGER.debug("Selected Version:" + state.getTlsContext().getSelectedProtocolVersion().name());
            return state.getTlsContext().getSelectedProtocolVersion() == toTest;
        }
    }

    private List<SignatureAndHashAlgorithm> getTls13SignatureAndHashAlgorithms() {
        List<SignatureAndHashAlgorithm> algos = new LinkedList<>();
        algos.add(SignatureAndHashAlgorithm.RSA_SHA256);
        algos.add(SignatureAndHashAlgorithm.RSA_SHA384);
        algos.add(SignatureAndHashAlgorithm.RSA_SHA512);
        algos.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        algos.add(SignatureAndHashAlgorithm.ECDSA_SHA384);
        algos.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA256);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA384);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA512);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512);
        return algos;
    }

    private List<ECPointFormat> getSupportedPointFormats(List<ProtocolVersion> supportedProtocolVersions) {
        Config tlsConfig = getCommonConfig(WorkflowTraceType.SHORT_HELLO, ProtocolVersion.TLS13, supportedProtocolVersions, getTls13Suite(), getTls13Groups());
        State state = new State(tlsConfig);
        setupKeyShares(state.getWorkflowTrace());
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            if (state.getTlsContext().getServerPointFormatsList() != null) {
                return state.getTlsContext().getServerPointFormatsList();
            } else {
                // no extension means only uncompressed
                List<ECPointFormat> format = new LinkedList<>();
                format.add(ECPointFormat.UNCOMPRESSED);
                return format;
            }
        } else {
            return null;
        }
    }

    private List<CipherSuite> getTls13Suite() {
        List<CipherSuite> tls13Suites = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.values()) {
            if (suite.isTLS13()) {
                tls13Suites.add(suite);
            }
        }
        return tls13Suites;
    }
    
    private List<NamedGroup> getTls13Groups() {
        List<NamedGroup> tls13Groups = new LinkedList<>();
        for (NamedGroup group : NamedGroup.values()) {
            if (group.isTls13()) {
                tls13Groups.add(group);
            }
        }
        return tls13Groups;
    }
    
    private List<ProtocolVersion> getTls13ProtocolVersions() {
        List<ProtocolVersion> tls13VersionList = new LinkedList<>();
        for (ProtocolVersion version : ProtocolVersion.values()) {
            if (version.isTLS13()) {
                tls13VersionList.add(version);
            }
        }
        return tls13VersionList;
    }

    @Override
    public ProbeResult executeTest() {
        List<ProtocolVersion> tls13VersionList = new LinkedList<>();
        for (ProtocolVersion version : ProtocolVersion.values()) {
            if (version.isTLS13()) {
                tls13VersionList.add(version);
            }
        }
        List<ProtocolVersion> supportedProtocolVersions = new LinkedList<>();
        List<ProtocolVersion> unsupportedProtocolVersions = new LinkedList<>();
        for (ProtocolVersion version : tls13VersionList) {
            if (isTls13Supported(version)) {
                supportedProtocolVersions.add(version);
            } else {
                unsupportedProtocolVersions.add(version);
            }
        }
        List<NamedGroup> supportedNamedGroups = getSupportedGroups();
        List<CipherSuite> supportedTls13Suites = getSupportedCiphersuites();
        List<ECPointFormat> supportedTls13PointFormats = getSupportedPointFormats(supportedProtocolVersions);
        return new Tls13Result(supportedProtocolVersions, unsupportedProtocolVersions, supportedNamedGroups,
                supportedTls13Suites, supportedTls13PointFormats);
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new Tls13Result(null, null, null, null, null);
    }
    
    private Config getCommonConfig(WorkflowTraceType traceType, ProtocolVersion highestProtocolVersion, List<ProtocolVersion> supportedProtocolVersions, List<CipherSuite> supportedCipherSuites, List<NamedGroup> supportedGroups)
    {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCiphersuites(supportedCipherSuites);
        tlsConfig.setHighestProtocolVersion(highestProtocolVersion);
        tlsConfig.setSupportedVersions(supportedProtocolVersions);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(traceType);
        tlsConfig.setDefaultClientNamedGroups(supportedGroups);
        tlsConfig.setAddECPointFormatExtension(false);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddSupportedVersionsExtension(true);
        tlsConfig.setAddKeyShareExtension(true);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setUseFreshRandom(true);
        tlsConfig.setSupportedSignatureAndHashAlgorithms(getTls13SignatureAndHashAlgorithms());
        
        return tlsConfig;
    }
    
    private Config getCommonConfig(WorkflowTraceType traceType, ProtocolVersion protocolVersion, List<CipherSuite> supportedCipherSuites, List<NamedGroup> supportedGroups)
    {
        List<ProtocolVersion> protocolVersionList = new LinkedList<>();
        protocolVersionList.add(protocolVersion);
        return getCommonConfig(traceType, protocolVersion, protocolVersionList, supportedCipherSuites, supportedGroups);
    }
    
    private WorkflowTrace setupKeyShares(WorkflowTrace workflowTrace)
    {
        ExtensionMessage keyShareExtension = WorkflowTraceUtil.getFirstSendExtension(ExtensionType.KEY_SHARE,
                workflowTrace);
        if (keyShareExtension == null) {
            keyShareExtension = WorkflowTraceUtil.getFirstSendExtension(ExtensionType.KEY_SHARE_OLD, workflowTrace);
        }
        if (keyShareExtension != null) {
            ((KeyShareExtensionMessage) keyShareExtension).setKeyShareList(new LinkedList<KeyShareEntry>());
        }
        return workflowTrace;
    }
}
