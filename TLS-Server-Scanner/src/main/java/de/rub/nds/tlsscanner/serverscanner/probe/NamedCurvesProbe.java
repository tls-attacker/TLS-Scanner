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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import static de.rub.nds.tlsscanner.serverscanner.probe.TlsProbe.LOGGER;
import de.rub.nds.tlsscanner.serverscanner.namedcurve.WitnessType;
import de.rub.nds.tlsscanner.serverscanner.namedcurve.NamedCurveWitness;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.NamedGroupResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class NamedCurvesProbe extends TlsProbe {

    private boolean testUsingRsa = true;
    private boolean testUsingEcdsaStatic = true;
    private boolean testUsingEcdsaEphemeral = true;

    // curves used for ecdsa in key exchange
    private List<NamedGroup> ecdsaPkGroupsStatic;
    private List<NamedGroup> ecdsaPkGroupsEphemeral;

    // curves used for ecdsa certificate signatures
    private List<NamedGroup> ecdsaCertSigGroupsStatic;
    private List<NamedGroup> ecdsaCertSigGroupsEphemeral;

    public NamedCurvesProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.NAMED_GROUPS, config);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            List<NamedGroup> groupsRsa = new LinkedList<>();
            Map<NamedGroup, NamedCurveWitness> groupsEcdsaStatic = new HashMap<>();
            Map<NamedGroup, NamedCurveWitness> groupsEcdsaEphemeral = new HashMap<>();

            if (testUsingRsa) {
                groupsRsa = getSupportedNamedGroupsRsa();
            }
            if (testUsingEcdsaStatic) {
                groupsEcdsaStatic = getSupportedNamedGroupsEcdsa(getEcdsaStaticCiphersuites(),
                        WitnessType.ECDSA_STATIC_ONLY, ecdsaPkGroupsStatic, ecdsaCertSigGroupsStatic);
            }
            if (testUsingEcdsaEphemeral) {
                groupsEcdsaEphemeral = getSupportedNamedGroupsEcdsa(getEcdsaEphemeralCiphersuites(),
                        WitnessType.ECDSA_EPHEMERAL_ONLY, ecdsaPkGroupsEphemeral, ecdsaCertSigGroupsEphemeral);
            }

            Map<NamedGroup, NamedCurveWitness> overallSupported = composeFullMap(groupsRsa, groupsEcdsaStatic,
                    groupsEcdsaEphemeral);

            return new NamedGroupResult(overallSupported);
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new NamedGroupResult(null, null);
        }
    }

    private List<NamedGroup> getSupportedNamedGroupsRsa() {

        Config tlsConfig = getBasicConfig();
        tlsConfig.setDefaultClientSupportedCiphersuites(getEcRsaCiphersuites());
        List<NamedGroup> toTestList = new ArrayList<>(Arrays.asList(NamedGroup.values()));
        TlsContext context;
        NamedGroup selectedGroup = null;
        List<NamedGroup> supportedNamedCurves = new LinkedList<>();
        do {
            context = testCurves(toTestList, tlsConfig);
            if (context != null) {
                selectedGroup = context.getSelectedGroup();
            }
            if (!toTestList.contains(selectedGroup)) {
                LOGGER.debug("Server chose a Curve we did not offer!");
                break;
            }
            if (context != null) {
                supportedNamedCurves.add(selectedGroup);
                toTestList.remove(selectedGroup);
            }
        } while (context != null || toTestList.size() > 0);
        return supportedNamedCurves;
    }

    private Map<NamedGroup, NamedCurveWitness> getSupportedNamedGroupsEcdsa(List<CipherSuite> cipherSuites,
            WitnessType type, List<NamedGroup> pkGroups, List<NamedGroup> sigGroups) {
        HashMap<NamedGroup, NamedCurveWitness> namedCurveMap = new HashMap<>();
        Config tlsConfig = getBasicConfig();
        tlsConfig.setDefaultClientSupportedCiphersuites(cipherSuites);
        List<NamedGroup> toTestList = new ArrayList<>(Arrays.asList(NamedGroup.values()));
        if (pkGroups != null) {
            TlsContext context;
            NamedGroup selectedGroup = null;
            NamedGroup certificateGroup = null;
            NamedGroup certificateSigGroup = null;
            // place signing groups at the bottom of the list, the server should
            // choose
            // all other first
            placeEcdsaPkGroupsLast(toTestList, pkGroups);
            if (sigGroups != null) {
                placeEcdsaSigGroupsLast(toTestList, sigGroups);
            }

            do {
                context = testCurves(toTestList, tlsConfig);
                if (context != null) {
                    selectedGroup = context.getSelectedGroup();
                    certificateGroup = context.getEcCertificateCurve();
                    certificateSigGroup = context.getEcCertificateSignatureCurve(); // might
                                                                                    // be
                                                                                    // null,
                                                                                    // if
                                                                                    // not
                                                                                    // ecdsa
                                                                                    // cert
                }
                if (!toTestList.contains(selectedGroup)) {
                    LOGGER.debug("Server chose a Curve we did not offer!");
                    break;
                }
                if (context != null) {
                    if (type == WitnessType.ECDSA_STATIC_ONLY) {
                        namedCurveMap.put(selectedGroup, new NamedCurveWitness(type, certificateGroup, null,
                                certificateSigGroup, null));
                    } else {
                        namedCurveMap.put(selectedGroup, new NamedCurveWitness(type, null, certificateGroup, null,
                                certificateSigGroup));
                    }

                    toTestList.remove(selectedGroup);
                }
            } while (context != null || toTestList.size() > 0);
        }
        return namedCurveMap;
    }

    private TlsContext testCurves(List<NamedGroup> curveList, Config tlsConfig) {
        tlsConfig.setDefaultClientNamedGroups(curveList);
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return state.getTlsContext();
        } else {
            LOGGER.debug("Did not receive a ServerHello, something went wrong or the Server has some intolerance");
            return null;
        }
    }

    private List<CipherSuite> getEcRsaCiphersuites() {
        List<CipherSuite> suiteList = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.values()) {
            if (suite.name().contains("ECDH") && suite.name().contains("RSA")) {
                suiteList.add(suite);
            }
        }
        return suiteList;
    }

    private List<CipherSuite> getEcdsaEphemeralCiphersuites() {
        List<CipherSuite> suiteList = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.values()) {
            if (suite.name().contains("ECDHE_") && suite.name().contains("ECDSA")) {
                suiteList.add(suite);
            }
        }
        return suiteList;
    }

    private List<CipherSuite> getEcdsaStaticCiphersuites() {
        List<CipherSuite> suiteList = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.values()) {
            if (suite.name().contains("ECDH_") && suite.name().contains("ECDSA")) {
                suiteList.add(suite);
            }
        }
        return suiteList;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if (report.getVersionSuitePairs() == null || report.getVersionSuitePairs().isEmpty()
                || report.getCertificateChainList() == null) {
            return false;
        }
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
        if (report.getResult(AnalyzedProperty.SUPPORTS_RSA) == TestResult.FALSE) {
            testUsingRsa = false;
        }

        testUsingEcdsaEphemeral = false;
        testUsingEcdsaStatic = false;
        for (VersionSuiteListPair pair : report.getVersionSuitePairs()) {
            if (pair.getVersion() != ProtocolVersion.TLS13) {
                for (CipherSuite cipherSuite : pair.getCiphersuiteList()) {
                    if (cipherSuite.isECDSA() && cipherSuite.isEphemeral()) {
                        testUsingEcdsaEphemeral = true;
                    } else if (cipherSuite.isECDSA() && !cipherSuite.isEphemeral()) {
                        testUsingEcdsaStatic = true;
                    }
                }
            }

        }
        ecdsaPkGroupsStatic = report.getEcdsaPkGroupsStatic();
        ecdsaPkGroupsEphemeral = report.getEcdsaPkGroupsEphemeral();

        ecdsaCertSigGroupsStatic = report.getEcdsaSigGroupsStatic();
        ecdsaCertSigGroupsEphemeral = report.getEcdsaSigGroupsStatic();
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new NamedGroupResult(new HashMap<>());
    }

    private Config getBasicConfig() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setStopActionsAfterIOException(true);
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

        return tlsConfig;
    }

    public void placeEcdsaPkGroupsLast(List<NamedGroup> groupList, List<NamedGroup> pkGroups) {
        for (int i = 0; i < groupList.size(); i++) {
            if (pkGroups.contains(groupList.get(0))) {
                groupList.remove(i);
                i--;
            }
        }

        groupList.addAll(pkGroups);
    }

    public void placeEcdsaSigGroupsLast(List<NamedGroup> groupList, List<NamedGroup> sigGroups) {
        for (int i = 0; i < groupList.size(); i++) {
            if (sigGroups.contains(groupList.get(0))) {
                groupList.remove(i);
                i--;
            }
        }

        groupList.addAll(sigGroups);
    private List<NamedGroup> getTls13SupportedGroups() {
        NamedGroup supportedGroup = null;
        List<NamedGroup> toTestList = new LinkedList<>();
        List<NamedGroup> supportedGroups = new LinkedList<>();
        for (NamedGroup group : NamedGroup.values()) {
            if (group.isTls13()) {
                toTestList.add(group);
            }
        }
        do {
            supportedGroup = getTls13SupportedGroup(toTestList);
            if (supportedGroup != null) {
                if (!toTestList.contains(supportedGroup)) {
                    LOGGER.warn("Server chose a group we did not offer:" + supportedGroup);
                    // TODO add to site report
                    return supportedGroups;
                }

                supportedGroups.add(supportedGroup);
                toTestList.remove(supportedGroup);
            }
        } while (supportedGroup != null && !toTestList.isEmpty());
        return supportedGroups;
    }

    public NamedGroup getTls13SupportedGroup(List<NamedGroup> groups) {
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
        List<KeyShareStoreEntry> keyShareEntryList = new ArrayList<>();
        tlsConfig.setDefaultClientKeyShareEntries(keyShareEntryList);
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
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return state.getTlsContext().getSelectedGroup();
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

    private Map<NamedGroup, NamedCurveWitness> composeFullMap(List<NamedGroup> rsaGroups,
            Map<NamedGroup, NamedCurveWitness> groupsEcdsaStatic,
            Map<NamedGroup, NamedCurveWitness> groupsEcdsaEphemeral) {
        List<NamedGroup> foundOverall = new LinkedList();
        for (NamedGroup group : rsaGroups) {
            if (!foundOverall.contains(group)) {
                foundOverall.add(group);
            }
        }
        for (NamedGroup group : groupsEcdsaStatic.keySet()) {
            if (!foundOverall.contains(group)) {
                foundOverall.add(group);
            }
        }
        for (NamedGroup group : groupsEcdsaEphemeral.keySet()) {
            if (!foundOverall.contains(group)) {
                foundOverall.add(group);
            }
        }

        HashMap<NamedGroup, NamedCurveWitness> groupMap = new HashMap<>();
        for (NamedGroup group : foundOverall) {
            NamedCurveWitness witness = null;
            if (rsaGroups.contains(group) && groupsEcdsaStatic.containsKey(group)
                    && groupsEcdsaEphemeral.containsKey(group)) {
                witness = new NamedCurveWitness(WitnessType.RSA_ECDSA_EPHEMERAL_STATIC, groupsEcdsaStatic.get(group)
                        .getEcdsaPkGroupStatic(), groupsEcdsaEphemeral.get(group).getEcdsaPkGroupEphemeral(),
                        groupsEcdsaStatic.get(group).getEcdsaSigGroupStatic(), groupsEcdsaStatic.get(group)
                                .getEcdsaSigGroupEphemeral());
            } else if (!rsaGroups.contains(group) && groupsEcdsaStatic.containsKey(group)
                    && groupsEcdsaEphemeral.containsKey(group)) {
                witness = new NamedCurveWitness(WitnessType.ECDSA_ONLY, groupsEcdsaStatic.get(group)
                        .getEcdsaPkGroupStatic(), groupsEcdsaEphemeral.get(group).getEcdsaPkGroupEphemeral(),
                        groupsEcdsaStatic.get(group).getEcdsaSigGroupStatic(), groupsEcdsaStatic.get(group)
                                .getEcdsaSigGroupEphemeral());
            } else if (rsaGroups.contains(group) && !groupsEcdsaStatic.containsKey(group)
                    && groupsEcdsaEphemeral.containsKey(group)) {
                witness = new NamedCurveWitness(WitnessType.RSA_ECDSA_EPHEMERAL, null, groupsEcdsaEphemeral.get(group)
                        .getEcdsaPkGroupEphemeral(), null, groupsEcdsaEphemeral.get(group).getEcdsaSigGroupEphemeral());
            } else if (rsaGroups.contains(group) && groupsEcdsaStatic.containsKey(group)
                    && !groupsEcdsaEphemeral.containsKey(group)) {
                witness = new NamedCurveWitness(WitnessType.RSA_ECSDA_STATIC, groupsEcdsaStatic.get(group)
                        .getEcdsaPkGroupStatic(), null, groupsEcdsaStatic.get(group).getEcdsaSigGroupStatic(), null);
            } else if (!rsaGroups.contains(group) && !groupsEcdsaStatic.containsKey(group)
                    && groupsEcdsaEphemeral.containsKey(group)) {
                witness = new NamedCurveWitness(WitnessType.ECDSA_EPHEMERAL_ONLY, null, groupsEcdsaEphemeral.get(group)
                        .getEcdsaPkGroupEphemeral(), null, groupsEcdsaStatic.get(group).getEcdsaSigGroupEphemeral());
            } else if (!rsaGroups.contains(group) && groupsEcdsaStatic.containsKey(group)
                    && !groupsEcdsaEphemeral.containsKey(group)) {
                witness = new NamedCurveWitness(WitnessType.ECDSA_STATIC_ONLY, groupsEcdsaStatic.get(group)
                        .getEcdsaPkGroupStatic(), null, groupsEcdsaStatic.get(group).getEcdsaSigGroupStatic(), null);
            } else if (rsaGroups.contains(group) && !groupsEcdsaStatic.containsKey(group)
                    && !groupsEcdsaEphemeral.containsKey(group)) {
                witness = new NamedCurveWitness(WitnessType.RSA_ONLY, null, null, null, null);
            }
            groupMap.put(group, witness);
        }

        return groupMap;
    }
}
