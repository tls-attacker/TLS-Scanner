/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.namedcurve.NamedCurveWitness;
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
 * @author Robert Merget - {@literal <robert.merget@rub.de>}
 */
public class NamedCurvesProbe extends TlsProbe {

    private boolean testUsingRsa = true;
    private boolean testUsingEcdsaStatic = true;
    private boolean testUsingEcdsaEphemeral = true;
    private boolean testUsingTls13 = true;

    // curves used for ecdsa in key exchange
    private List<NamedGroup> ecdsaPkGroupsEphemeral;
    private List<NamedGroup> ecdsaPkGroupsTls13;

    // curves used for ecdsa certificate signatures
    private List<NamedGroup> ecdsaCertSigGroupsStatic;
    private List<NamedGroup> ecdsaCertSigGroupsEphemeral;
    private List<NamedGroup> ecdsaCertSigGroupsTls13;

    private TestResult ignoresEcdsaGroupDisparity = TestResult.FALSE;

    public NamedCurvesProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.NAMED_GROUPS, config);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            Map<NamedGroup, NamedCurveWitness> groupsRsa = new HashMap<>();
            Map<NamedGroup, NamedCurveWitness> groupsEcdsaStatic = new HashMap<>();
            Map<NamedGroup, NamedCurveWitness> groupsEcdsaEphemeral = new HashMap<>();
            Map<NamedGroup, NamedCurveWitness> groupsTls13 = new HashMap<>();

            TestResult supportsExplicitPrime = getExplicitCurveSupport(EllipticCurveType.EXPLICIT_PRIME);
            TestResult supportsExplicitChar2 = getExplicitCurveSupport(EllipticCurveType.EXPLICIT_CHAR2);

            if (testUsingRsa) {
                groupsRsa = getSupportedNamedGroupsRsa();
            }
            if (testUsingEcdsaStatic) {
                groupsEcdsaStatic =
                    getSupportedNamedGroupsEcdsa(getEcdsaStaticCipherSuites(), null, ecdsaCertSigGroupsStatic);
            }
            if (testUsingEcdsaEphemeral) {
                groupsEcdsaEphemeral = getSupportedNamedGroupsEcdsa(getEcdsaEphemeralCipherSuites(),
                    ecdsaPkGroupsEphemeral, ecdsaCertSigGroupsEphemeral);
            }
            if (testUsingTls13) {
                groupsTls13 = getTls13SupportedGroups();
            }

            Map<NamedGroup, NamedCurveWitness> overallSupported =
                composeFullMap(groupsRsa, groupsEcdsaStatic, groupsEcdsaEphemeral);

            TestResult groupsDependOnCipherSuite =
                getGroupsDependOnCipherSuite(overallSupported, groupsRsa, groupsEcdsaStatic, groupsEcdsaEphemeral);

            return new NamedGroupResult(overallSupported, groupsTls13, supportsExplicitPrime, supportsExplicitChar2,
                groupsDependOnCipherSuite, ignoresEcdsaGroupDisparity);
        } catch (Exception e) {
            LOGGER.error("Could not scan for " + getProbeName(), e);
            return getCouldNotExecuteResult();
        }
    }

    private Map<NamedGroup, NamedCurveWitness> getSupportedNamedGroupsRsa() {

        Config tlsConfig = getBasicConfig();
        tlsConfig.setDefaultClientSupportedCipherSuites(getEcRsaCipherSuites());
        List<NamedGroup> toTestList = new ArrayList<>(Arrays.asList(NamedGroup.values()));
        TlsContext context;
        NamedGroup selectedGroup = null;
        Map<NamedGroup, NamedCurveWitness> supportedNamedCurves = new HashMap<>();
        do {
            context = testCurves(toTestList, tlsConfig);

            if (context != null) {
                selectedGroup = context.getSelectedGroup();

                if (!toTestList.contains(selectedGroup)) {
                    LOGGER.debug("Server chose a Curve we did not offer!");
                    break;
                }

                supportedNamedCurves.put(selectedGroup, new NamedCurveWitness(context.getSelectedCipherSuite()));
                toTestList.remove(selectedGroup);
            }
        } while (context != null && toTestList.size() > 0);
        return supportedNamedCurves;
    }

    private Map<NamedGroup, NamedCurveWitness> getSupportedNamedGroupsEcdsa(List<CipherSuite> cipherSuites,
        List<NamedGroup> pkGroups, List<NamedGroup> sigGroups) {
        HashMap<NamedGroup, NamedCurveWitness> namedCurveMap = new HashMap<>();
        Config tlsConfig = getBasicConfig();
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites);
        List<NamedGroup> toTestList = new ArrayList<>(Arrays.asList(NamedGroup.values()));

        TlsContext context;
        NamedGroup selectedGroup = null;
        NamedGroup certificateGroup = null;
        NamedGroup certificateSigGroup = null;
        // place signing groups at the bottom of the list, the server should
        // choose
        // all other first
        if (pkGroups != null) {
            placeRequiredGroupsLast(toTestList, pkGroups);
        }
        if (sigGroups != null) {
            placeRequiredGroupsLast(toTestList, sigGroups);
        }

        do {
            context = testCurves(toTestList, tlsConfig);

            if (context != null) {

                selectedGroup = context.getSelectedGroup();
                certificateGroup = context.getEcCertificateCurve();
                certificateSigGroup = context.getEcCertificateSignatureCurve();

                // remove groups that are not required by the server even
                // if they are used for the certificate or KEX signature
                if (!toTestList.contains(certificateGroup) && certificateSigGroup != null) {
                    ignoresEcdsaGroupDisparity = TestResult.TRUE;
                    certificateGroup = null;
                }
                if (!toTestList.contains(certificateSigGroup) && certificateSigGroup != null) {
                    ignoresEcdsaGroupDisparity = TestResult.TRUE;
                    certificateSigGroup = null;
                }

                if (!toTestList.contains(selectedGroup)) {
                    LOGGER.debug("Server chose a Curve we did not offer!");
                    break;
                }
                if (cipherSuites.get(0).isEphemeral()) {
                    namedCurveMap.put(selectedGroup, new NamedCurveWitness(certificateGroup, null, certificateSigGroup,
                        context.getSelectedCipherSuite()));
                } else {
                    namedCurveMap.put(selectedGroup,
                        new NamedCurveWitness(null, certificateSigGroup, null, context.getSelectedCipherSuite()));

                }

                toTestList.remove(selectedGroup);
            }
        } while (context != null && toTestList.size() > 0);
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

    private List<CipherSuite> getEcCipherSuites() {
        List<CipherSuite> suiteList = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.values()) {
            if (suite.name().contains("ECDH")) {
                suiteList.add(suite);
            }
        }
        return suiteList;
    }

    private List<CipherSuite> getEcRsaCipherSuites() {
        List<CipherSuite> suiteList = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.values()) {
            if (suite.name().contains("ECDH") && suite.name().contains("RSA")) {
                suiteList.add(suite);
            }
        }
        return suiteList;
    }

    private List<CipherSuite> getEcdsaEphemeralCipherSuites() {
        List<CipherSuite> suiteList = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.values()) {
            if (suite.name().contains("ECDHE_") && suite.name().contains("ECDSA")) {
                suiteList.add(suite);
            }
        }
        return suiteList;
    }

    private List<CipherSuite> getEcdsaStaticCipherSuites() {
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
            || report.getCertificateChainList() == null || !report.isProbeAlreadyExecuted(ProbeType.PROTOCOL_VERSION)) {
            return false;
        }
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
        if (report.getResult(AnalyzedProperty.SUPPORTS_RSA_CERT) == TestResult.FALSE) {
            testUsingRsa = false;
        }

        testUsingEcdsaEphemeral = false;
        testUsingEcdsaStatic = false;
        for (VersionSuiteListPair pair : report.getVersionSuitePairs()) {
            if (pair.getVersion() != ProtocolVersion.TLS13) {
                for (CipherSuite cipherSuite : pair.getCipherSuiteList()) {
                    if (cipherSuite.isECDSA() && cipherSuite.isEphemeral()) {
                        testUsingEcdsaEphemeral = true;
                    } else if (cipherSuite.isECDSA() && !cipherSuite.isEphemeral()) {
                        testUsingEcdsaStatic = true;
                    }
                }
            }

        }
        if (report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) != TestResult.TRUE) {
            testUsingTls13 = false;
        }
        ecdsaPkGroupsEphemeral = report.getEcdsaPkGroupsEphemeral();
        ecdsaPkGroupsTls13 = report.getEcdsaPkGroupsTls13();

        ecdsaCertSigGroupsStatic = report.getEcdsaSigGroupsStatic();
        ecdsaCertSigGroupsEphemeral = report.getEcdsaSigGroupsStatic();
        ecdsaCertSigGroupsTls13 = report.getEcdsaSigGroupsTls13();
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new NamedGroupResult(new HashMap<>(), new HashMap<>(), TestResult.COULD_NOT_TEST,
            TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST);
    }

    private TestResult getExplicitCurveSupport(EllipticCurveType curveType) {
        Config tlsConfig = getBasicConfig();
        if (curveType == EllipticCurveType.EXPLICIT_PRIME) {
            tlsConfig.setDefaultClientNamedGroups(NamedGroup.EXPLICIT_PRIME);
        } else {
            tlsConfig.setDefaultClientNamedGroups(NamedGroup.EXPLICIT_CHAR2);
        }

        tlsConfig.setDefaultClientSupportedCipherSuites(getEcCipherSuites());
        State state = new State(tlsConfig);
        executeState(state);

        if (WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.UNKNOWN, state.getWorkflowTrace())) {
            return TestResult.UNCERTAIN;
        } else if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE,
            state.getWorkflowTrace())) {
            HandshakeMessage skeMsg = WorkflowTraceUtil
                .getFirstReceivedMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, state.getWorkflowTrace());
            if (skeMsg instanceof ECDHEServerKeyExchangeMessage) {
                ECDHEServerKeyExchangeMessage kex = (ECDHEServerKeyExchangeMessage) skeMsg;
                if (kex.getGroupType().getValue() == curveType.getValue()) {
                    return TestResult.TRUE;
                }
            }

        }
        return TestResult.FALSE;
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
        tlsConfig.setAddRenegotiationInfoExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);

        return tlsConfig;
    }

    public void placeRequiredGroupsLast(List<NamedGroup> groupList, List<NamedGroup> sigGroups) {
        for (int i = 0; i < groupList.size(); i++) {
            if (sigGroups.contains(groupList.get(i))) {
                groupList.remove(i);
                i--;
            }
        }

        groupList.addAll(sigGroups);
    }

    private Map<NamedGroup, NamedCurveWitness> getTls13SupportedGroups() {
        Map<NamedGroup, NamedCurveWitness> namedCurveMap = new HashMap<>();
        NamedGroup selectedGroup = null;
        NamedGroup certificateGroup = null;
        NamedGroup certificateSigGroup = null;
        TlsContext context = null;
        List<NamedGroup> toTestList = NamedGroup.getImplemented();
        List<NamedGroup> supportedGroups = new LinkedList<>();
        if (ecdsaPkGroupsTls13 != null) {
            placeRequiredGroupsLast(supportedGroups, ecdsaPkGroupsTls13);
        }
        if (ecdsaCertSigGroupsTls13 != null) {
            placeRequiredGroupsLast(supportedGroups, ecdsaCertSigGroupsTls13);
        }
        do {
            context = getTls13SupportedGroup(toTestList);

            if (context != null) {
                selectedGroup = context.getSelectedGroup();
                certificateGroup = context.getEcCertificateCurve();
                certificateSigGroup = context.getEcCertificateSignatureCurve();

                if (!toTestList.contains(certificateGroup) && certificateGroup != null) {
                    ignoresEcdsaGroupDisparity = TestResult.TRUE;
                    certificateGroup = null;
                }

                if (!toTestList.contains(certificateSigGroup) && certificateSigGroup != null) {
                    ignoresEcdsaGroupDisparity = TestResult.TRUE;
                    certificateSigGroup = null;
                }

                if (!toTestList.contains(selectedGroup)) {
                    LOGGER.warn("Server chose a group we did not offer:" + selectedGroup);
                    // TODO add to site report
                    break;
                }

                namedCurveMap.put(selectedGroup, new NamedCurveWitness(certificateGroup, null, certificateSigGroup,
                    context.getSelectedCipherSuite()));
                toTestList.remove(selectedGroup);
            }
        } while (context != null && !toTestList.isEmpty());
        return namedCurveMap;
    }

    public TlsContext getTls13SupportedGroup(List<NamedGroup> groups) {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(CipherSuite.getImplementedTls13CipherSuites());
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS13);
        tlsConfig.setSupportedVersions(ProtocolVersion.TLS13);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.HELLO);
        tlsConfig.setDefaultClientNamedGroups(groups);
        tlsConfig.setDefaultClientKeyShareNamedGroups(groups);
        tlsConfig.setAddECPointFormatExtension(false);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddSupportedVersionsExtension(true);
        tlsConfig.setAddKeyShareExtension(true);
        tlsConfig.setAddCertificateStatusRequestExtension(true);
        tlsConfig.setUseFreshRandom(true);
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(
            SignatureAndHashAlgorithm.getTls13SignatureAndHashAlgorithms());
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return state.getTlsContext();
        } else {
            LOGGER.debug("Did not receive ServerHello Message");
            LOGGER.debug(state.getWorkflowTrace().toString());
            return null;
        }
    }

    private Map<NamedGroup, NamedCurveWitness> composeFullMap(Map<NamedGroup, NamedCurveWitness> rsaGroups,
        Map<NamedGroup, NamedCurveWitness> groupsEcdsaStatic, Map<NamedGroup, NamedCurveWitness> groupsEcdsaEphemeral) {
        List<NamedGroup> foundOverall = new LinkedList();
        for (NamedGroup group : rsaGroups.keySet()) {
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
            NamedCurveWitness witness = new NamedCurveWitness();
            if (rsaGroups.containsKey(group)) {
                witness.getCipherSuites().addAll(rsaGroups.get(group).getCipherSuites());
            }
            if (groupsEcdsaStatic.containsKey(group)) {
                witness.getCipherSuites().addAll(groupsEcdsaStatic.get(group).getCipherSuites());
                witness.setEcdsaSigGroupStatic(groupsEcdsaStatic.get(group).getEcdsaSigGroupStatic());
            }
            if (groupsEcdsaEphemeral.containsKey(group)) {
                witness.getCipherSuites().addAll(groupsEcdsaEphemeral.get(group).getCipherSuites());
                witness.setEcdsaPkGroupEphemeral(groupsEcdsaEphemeral.get(group).getEcdsaPkGroupEphemeral());
                witness.setEcdsaSigGroupEphemeral(groupsEcdsaEphemeral.get(group).getEcdsaSigGroupEphemeral());
            }
            groupMap.put(group, witness);
        }

        return groupMap;
    }

    private TestResult getGroupsDependOnCipherSuite(Map<NamedGroup, NamedCurveWitness> overallSupported,
        Map<NamedGroup, NamedCurveWitness> groupsRsa, Map<NamedGroup, NamedCurveWitness> groupsEcdsaStatic,
        Map<NamedGroup, NamedCurveWitness> groupsEcdsaEphemeral) {
        for (NamedGroup group : overallSupported.keySet()) {
            if (((testUsingRsa && !groupsRsa.containsKey(group))
                || (testUsingEcdsaStatic && !groupsEcdsaStatic.containsKey(group))
                || (testUsingEcdsaEphemeral && !groupsEcdsaEphemeral.containsKey(group))) && group.isCurve()) {
                return TestResult.TRUE;
            }
        }
        return TestResult.FALSE;
    }
}
