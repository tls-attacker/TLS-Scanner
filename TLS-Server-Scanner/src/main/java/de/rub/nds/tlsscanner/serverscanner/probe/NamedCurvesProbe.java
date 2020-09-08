/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import static de.rub.nds.tlsscanner.serverscanner.probe.TlsProbe.LOGGER;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.NamedGroupResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class NamedCurvesProbe extends TlsProbe {

    public NamedCurvesProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.NAMED_GROUPS, config);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            List<NamedGroup> groups = getSupportedNamedGroups();
            List<NamedGroup> tls13Groups = getTls13SupportedGroups();
            return new NamedGroupResult(groups, tls13Groups);
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new NamedGroupResult(null, null);
        }
    }

    private List<NamedGroup> getSupportedNamedGroups() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setDefaultClientSupportedCiphersuites(getEcCiphersuites());
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.HELLO);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        List<NamedGroup> toTestList = new ArrayList<>(Arrays.asList(NamedGroup.values()));
        NamedGroup selectedGroup;
        List<NamedGroup> supportedNamedCurves = new LinkedList<>();
        do {
            selectedGroup = testCurves(toTestList, tlsConfig);
            if (!toTestList.contains(selectedGroup)) {
                LOGGER.debug("Server chose a Curve we did not offer!");
                break;
            }
            if (selectedGroup != null) {
                supportedNamedCurves.add(selectedGroup);
                toTestList.remove(selectedGroup);
            }
        } while (selectedGroup != null || toTestList.size() > 0);
        return supportedNamedCurves;
    }

    private NamedGroup testCurves(List<NamedGroup> curveList, Config tlsConfig) {
        tlsConfig.setDefaultClientNamedGroups(curveList);
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return state.getTlsContext().getSelectedGroup();
        } else {
            LOGGER.debug("Did not receive a ServerHello, something went wrong or the Server has some intolerance");
            return null;
        }
    }

    private List<CipherSuite> getEcCiphersuites() {
        List<CipherSuite> suiteList = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.values()) {
            if (suite.name().contains("ECDH")) {
                suiteList.add(suite);
            }
        }
        return suiteList;
    }

    private List<NamedGroup> getTls13SupportedGroups() {
        List<NamedGroup> tempSupportedGroups = null;
        List<NamedGroup> toTestList = new LinkedList<>();
        List<NamedGroup> supportedGroups = new LinkedList<>();
        for (NamedGroup group : NamedGroup.values()) {
            if (group.isTls13()) {
                toTestList.add(group);
            }
        }
        do {
            tempSupportedGroups = getTls13SupportedGroups(toTestList);
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

    public List<NamedGroup> getTls13SupportedGroups(List<NamedGroup> groups) {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCiphersuites(CipherSuite.getImplementedTls13CipherSuites());
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS13);
        tlsConfig.setSupportedVersions(ProtocolVersion.TLS13);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.HELLO);
        tlsConfig.setDefaultClientNamedGroups(groups);
        tlsConfig.setAddECPointFormatExtension(false);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddSupportedVersionsExtension(true);
        tlsConfig.setAddKeyShareExtension(true);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setAddCertificateStatusRequestExtension(true);
        tlsConfig.setUseFreshRandom(true);
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(SignatureAndHashAlgorithm
                .getTls13SignatureAndHashAlgorithms());
        State state = new State(tlsConfig);
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

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new NamedGroupResult(new LinkedList<>(), new LinkedList<>());
    }
}
