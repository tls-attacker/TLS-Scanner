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
import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.rating.TestResult;
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
        Config tlsConfig = getCommonConfig(WorkflowTraceType.SHORT_HELLO, ProtocolVersion.TLS13,
                getTls13ProtocolVersions(), toTestList, getTls13Groups());
        State state = new State(tlsConfig);
        setupEmptyKeyShares(state.getWorkflowTrace());
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
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
        Config tlsConfig = getCommonConfig(WorkflowTraceType.SHORT_HELLO, ProtocolVersion.TLS13,
                getTls13ProtocolVersions(), getTls13Suite(), group);
        State state = new State(tlsConfig);
        setupEmptyKeyShares(state.getWorkflowTrace());
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
        setupEmptyKeyShares(state.getWorkflowTrace());
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

    private TestResult getSECPCompressionSupported(List<ProtocolVersion> supportedProtocolVersions) {
        // SECP curves in TLS 1.3 don't use compression, some implementations
        // might still accept compression
        List<NamedGroup> secpGroups = new LinkedList<>();
        for (NamedGroup group : getTls13Groups()) {
            if (group.name().contains("SECP")) {
                secpGroups.add(group);
            }
        }
        Config tlsConfig = getCommonConfig(WorkflowTraceType.HELLO, ProtocolVersion.TLS13, supportedProtocolVersions,
                getTls13Suite(), secpGroups);
        tlsConfig.setDefaultClientSupportedPointFormats(ECPointFormat.ANSIX962_COMPRESSED_PRIME);
        tlsConfig.setDefaultSelectedPointFormat(ECPointFormat.ANSIX962_COMPRESSED_PRIME);
        State state = new State(tlsConfig);

        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            return TestResult.TRUE;
        }
        return TestResult.FALSE;
    }

    private TestResult getIssuesSessionTicket(List<ProtocolVersion> supportedProtocolVersions) {
        Config tlsConfig = getCommonConfig(WorkflowTraceType.HANDSHAKE, ProtocolVersion.TLS13,
                supportedProtocolVersions, getTls13Suite(), getImplementedTls13Groups());
        List<PskKeyExchangeMode> pskKex = new LinkedList<>();
        pskKex.add(PskKeyExchangeMode.PSK_DHE_KE);
        pskKex.add(PskKeyExchangeMode.PSK_KE);
        tlsConfig.setPSKKeyExchangeModes(pskKex);
        tlsConfig.setAddPSKKeyExchangeModesExtension(true);
        State state = new State(tlsConfig);
        state.getWorkflowTrace()
                .addTlsAction(
                        new ReceiveAction(tlsConfig.getDefaultClientConnection().getAlias(),
                                new NewSessionTicketMessage(false)));

        executeState(state);
        if (state.getWorkflowTrace().getLastMessageAction().executedAsPlanned()) {
            return TestResult.TRUE;
        }
        return TestResult.FALSE;
    }

    private TestResult getSupportsPskDhe(List<ProtocolVersion> supportedProtocolVersions) {
        Config tlsConfig = getCommonConfig(WorkflowTraceType.HANDSHAKE, ProtocolVersion.TLS13,
                supportedProtocolVersions, getTls13Suite(), getImplementedTls13Groups());
        tlsConfig.setTls13BackwardsCompatibilityMode(Boolean.TRUE);
        List<PskKeyExchangeMode> pskKex = new LinkedList<>();
        pskKex.add(PskKeyExchangeMode.PSK_DHE_KE);
        tlsConfig.setPSKKeyExchangeModes(pskKex);
        tlsConfig.setAddPSKKeyExchangeModesExtension(true);
        State state = new State(tlsConfig);
        WorkflowTrace trace = state.getWorkflowTrace();

        trace.addTlsAction(new ReceiveAction(tlsConfig.getDefaultClientConnection().getAlias(),
                new NewSessionTicketMessage(false)));
        trace.addTlsAction(new ResetConnectionAction(tlsConfig.getDefaultClientConnection().getAlias()));

        tlsConfig.setAddPreSharedKeyExtension(Boolean.TRUE);
        WorkflowTrace secondHandshake = new WorkflowConfigurationFactory(tlsConfig).createWorkflowTrace(
                WorkflowTraceType.HANDSHAKE, RunningModeType.CLIENT);

        // remove certificate messages from 2nd handshake
        ReceiveAction firstServerMsgs = (ReceiveAction) secondHandshake.getTlsActions().get(1);
        List<ProtocolMessage> newExpectedMsgs = new LinkedList<>();
        for (ProtocolMessage msg : firstServerMsgs.getExpectedMessages()) {
            if (!(msg instanceof CertificateMessage || msg instanceof CertificateVerifyMessage)) {
                newExpectedMsgs.add(msg);
            }
        }
        firstServerMsgs.setExpectedMessages(newExpectedMsgs);
        trace.addTlsActions(secondHandshake.getTlsActions());

        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            return TestResult.TRUE;
        }
        return TestResult.FALSE;
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

    private List<NamedGroup> getImplementedTls13Groups() {
        List<NamedGroup> tls13Groups = new LinkedList<>();
        for (NamedGroup group : NamedGroup.values()) {
            if (group.isTls13() && NamedGroup.getImplemented().contains(group)) {
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
        try {
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
            TestResult supportsSECPCompression = null;
            if (containsSECPGroup(supportedNamedGroups)) {
                supportsSECPCompression = getSECPCompressionSupported(supportedProtocolVersions);
            }
            TestResult issuesSessionTicket = getIssuesSessionTicket(supportedProtocolVersions);
            TestResult supportsPskDhe = getSupportsPskDhe(supportedProtocolVersions);
            return new Tls13Result(supportedProtocolVersions, unsupportedProtocolVersions, supportedNamedGroups,
                    supportedTls13Suites, supportsSECPCompression, issuesSessionTicket, supportsPskDhe);
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new Tls13Result(null, null, null, null, TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST,
                    TestResult.ERROR_DURING_TEST);
        }
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
        return new Tls13Result(null, null, null, null, null, null, null);
    }

    private Config getCommonConfig(WorkflowTraceType traceType, ProtocolVersion highestProtocolVersion,
            List<ProtocolVersion> supportedProtocolVersions, List<CipherSuite> supportedCipherSuites,
            List<NamedGroup> supportedGroups) {
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
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(getTls13SignatureAndHashAlgorithms());

        return tlsConfig;
    }

    private Config getCommonConfig(WorkflowTraceType traceType, ProtocolVersion protocolVersion,
            List<CipherSuite> supportedCipherSuites, List<NamedGroup> supportedGroups) {
        List<ProtocolVersion> protocolVersionList = new LinkedList<>();
        protocolVersionList.add(protocolVersion);
        return getCommonConfig(traceType, protocolVersion, protocolVersionList, supportedCipherSuites, supportedGroups);
    }

    private WorkflowTrace setupEmptyKeyShares(WorkflowTrace workflowTrace) {
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

    private boolean containsSECPGroup(List<NamedGroup> groups) {
        for (NamedGroup group : groups) {
            if (group.name().contains("SECP")) {
                return true;
            }
        }
        return false;
    }
}
