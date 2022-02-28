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
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
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
import de.rub.nds.tlsscanner.serverscanner.probe.namedgroup.NamedGroupWitness;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResults;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.NamedGroupResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class NamedGroupsProbe extends TlsProbe {

    Set<CipherSuite> supportedCipherSuites;

    // curves used for ecdsa in key exchange
    private List<NamedGroup> ecdsaPkGroupsEphemeral;
    private List<NamedGroup> ecdsaPkGroupsTls13;

    // curves used for ecdsa certificate signatures
    private List<NamedGroup> ecdsaCertSigGroupsStatic;
    private List<NamedGroup> ecdsaCertSigGroupsEphemeral;
    private List<NamedGroup> ecdsaCertSigGroupsTls13;

    private TestResult ignoresEcdsaGroupDisparity = TestResults.FALSE;

    public NamedGroupsProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.NAMED_GROUPS, config);
    }

    @Override
    public ProbeResult executeTest() {
        Map<NamedGroup, NamedGroupWitness> overallSupported = new HashMap<>();

        addGroupsFound(overallSupported,
            getSupportedNamedGroups(getCipherSuiteByKeyExchange(KeyExchangeAlgorithm.DHE_RSA), false),
            KeyExchangeAlgorithm.DHE_RSA);
        addGroupsFound(overallSupported,
            getSupportedNamedGroups(getCipherSuiteByKeyExchange(KeyExchangeAlgorithm.DHE_DSS), false),
            KeyExchangeAlgorithm.DHE_DSS);
        addGroupsFound(overallSupported,
            getSupportedNamedGroups(getCipherSuiteByKeyExchange(KeyExchangeAlgorithm.DH_ANON), false),
            KeyExchangeAlgorithm.DH_ANON);

        addGroupsFound(overallSupported,
            getSupportedNamedGroups(getCipherSuiteByKeyExchange(KeyExchangeAlgorithm.ECDH_ANON), true),
            KeyExchangeAlgorithm.ECDH_ANON);
        addGroupsFound(overallSupported,
            getSupportedNamedGroups(
                getCipherSuiteByKeyExchange(KeyExchangeAlgorithm.ECDHE_RSA, KeyExchangeAlgorithm.ECDH_RSA), true),
            KeyExchangeAlgorithm.ECDHE_RSA);
        addGroupsFound(overallSupported,
            getSupportedNamedCurvesEcdsa(getCipherSuiteByKeyExchange(KeyExchangeAlgorithm.ECDHE_ECDSA),
                ecdsaPkGroupsEphemeral, ecdsaCertSigGroupsEphemeral),
            KeyExchangeAlgorithm.ECDHE_ECDSA);
        addGroupsFound(overallSupported,
            getSupportedNamedCurvesEcdsa(getCipherSuiteByKeyExchange(KeyExchangeAlgorithm.ECDH_ECDSA), null,
                ecdsaCertSigGroupsStatic),
            KeyExchangeAlgorithm.ECDH_ECDSA);
        TestResult supportsExplicitPrime = getExplicitCurveSupport(EllipticCurveType.EXPLICIT_PRIME);
        TestResult supportsExplicitChar2 = getExplicitCurveSupport(EllipticCurveType.EXPLICIT_CHAR2);

        Map<NamedGroup, NamedGroupWitness> groupsTls13 = getTls13SupportedGroups();

        TestResult groupsDependOnCipherSuite = getGroupsDependOnCipherSuite(overallSupported);

        return new NamedGroupResult(overallSupported, groupsTls13, supportsExplicitPrime, supportsExplicitChar2,
            groupsDependOnCipherSuite, ignoresEcdsaGroupDisparity);

    }

    private Map<NamedGroup, NamedGroupWitness> getSupportedNamedGroups(List<CipherSuite> cipherSuites,
        boolean useCurves) {
        Map<NamedGroup, NamedGroupWitness> supportedNamedGroups = new HashMap<>();

        if (cipherSuites.isEmpty()) {
            return supportedNamedGroups;
        }

        Config tlsConfig = getBasicConfig();
        tlsConfig.setDefaultClientSupportedCipherSuites((cipherSuites));
        List<NamedGroup> toTestList = Arrays.asList(NamedGroup.values()).stream().filter(group -> {
            if (useCurves) {
                return group.isCurve();
            } else {
                return group.isDhGroup();
            }
        }).collect(Collectors.toList());

        TlsContext context;
        NamedGroup selectedGroup = null;

        do {
            context = testGroups(toTestList, tlsConfig);

            if (context != null) {
                selectedGroup = context.getSelectedGroup();

                if (!toTestList.contains(selectedGroup)) {
                    LOGGER.debug("Server chose a Named Group we did not offer!");
                    break;
                }

                supportedNamedGroups.put(selectedGroup, new NamedGroupWitness(context.getSelectedCipherSuite()));
                toTestList.remove(selectedGroup);
            }
        } while (context != null && !toTestList.isEmpty());
        return supportedNamedGroups;
    }

    private Map<NamedGroup, NamedGroupWitness> getSupportedNamedCurvesEcdsa(List<CipherSuite> cipherSuites,
        List<NamedGroup> pkGroups, List<NamedGroup> sigGroups) {
        HashMap<NamedGroup, NamedGroupWitness> namedCurveMap = new HashMap<>();

        if (cipherSuites.isEmpty()) {
            return namedCurveMap;
        }

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
            context = testGroups(toTestList, tlsConfig);

            if (context != null) {

                selectedGroup = context.getSelectedGroup();
                certificateGroup = context.getEcCertificateCurve();
                certificateSigGroup = context.getEcCertificateSignatureCurve();

                // remove groups that are not required by the server even
                // if they are used for the certificate or KEX signature
                if (!toTestList.contains(certificateGroup) && certificateSigGroup != null) {
                    ignoresEcdsaGroupDisparity = TestResults.TRUE;
                    certificateGroup = null;
                }
                if (!toTestList.contains(certificateSigGroup) && certificateSigGroup != null) {
                    ignoresEcdsaGroupDisparity = TestResults.TRUE;
                    certificateSigGroup = null;
                }

                if (!toTestList.contains(selectedGroup)) {
                    LOGGER.debug("Server chose a Curve we did not offer!");
                    break;
                }
                if (cipherSuites.get(0).isEphemeral()) {
                    namedCurveMap.put(selectedGroup, new NamedGroupWitness(certificateGroup, null, certificateSigGroup,
                        context.getSelectedCipherSuite()));
                } else {
                    namedCurveMap.put(selectedGroup,
                        new NamedGroupWitness(null, certificateSigGroup, null, context.getSelectedCipherSuite()));

                }

                toTestList.remove(selectedGroup);
            }
        } while (context != null && !toTestList.isEmpty());
        return namedCurveMap;
    }

    private TlsContext testGroups(List<NamedGroup> groupList, Config tlsConfig) {
        tlsConfig.setDefaultClientNamedGroups(groupList);
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return state.getTlsContext();
        } else {
            LOGGER.debug("Did not receive a ServerHello, something went wrong or the Server has some intolerance");
            return null;
        }
    }

    private List<CipherSuite> getCipherSuiteByKeyExchange(KeyExchangeAlgorithm... algorithms) {
        List<CipherSuite> chosenCipherSuites = new LinkedList<>();
        List<KeyExchangeAlgorithm> algorithmList = Arrays.asList(algorithms);
        for (CipherSuite cipherSuite : supportedCipherSuites) {
            if (cipherSuite.isRealCipherSuite() && !cipherSuite.isTLS13()
                && algorithmList.contains(AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite))) {
                chosenCipherSuites.add(cipherSuite);
            }
        }
        return chosenCipherSuites;
    }

    private List<CipherSuite> getAllEcCipherSuites() {
        List<CipherSuite> suiteList = new LinkedList<>();
        for (CipherSuite suite : supportedCipherSuites) {
            if (suite.isRealCipherSuite() && !suite.isTLS13()
                && AlgorithmResolver.getKeyExchangeAlgorithm(suite).isKeyExchangeEcdh()) {
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
        ecdsaPkGroupsEphemeral = report.getEcdsaPkGroupsEphemeral();
        ecdsaPkGroupsTls13 = report.getEcdsaPkGroupsTls13();
        ecdsaCertSigGroupsStatic = report.getEcdsaSigGroupsStatic();
        ecdsaCertSigGroupsEphemeral = report.getEcdsaSigGroupsStatic();
        ecdsaCertSigGroupsTls13 = report.getEcdsaSigGroupsTls13();

        supportedCipherSuites = report.getCipherSuites();
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new NamedGroupResult(new HashMap<>(), new HashMap<>(), TestResults.COULD_NOT_TEST,
            TestResults.COULD_NOT_TEST, TestResults.COULD_NOT_TEST, TestResults.COULD_NOT_TEST);
    }

    private TestResult getExplicitCurveSupport(EllipticCurveType curveType) {
        Config tlsConfig = getBasicConfig();
        if (curveType == EllipticCurveType.EXPLICIT_PRIME) {
            tlsConfig.setDefaultClientNamedGroups(NamedGroup.EXPLICIT_PRIME);
        } else {
            tlsConfig.setDefaultClientNamedGroups(NamedGroup.EXPLICIT_CHAR2);
        }
        List<CipherSuite> allEcCipherSuites = getAllEcCipherSuites();
        if (allEcCipherSuites.isEmpty()) {
            return TestResults.COULD_NOT_TEST;
        }

        tlsConfig.setDefaultClientSupportedCipherSuites(allEcCipherSuites);
        State state = new State(tlsConfig);
        executeState(state);

        if (WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.UNKNOWN, state.getWorkflowTrace())) {
            return TestResults.UNCERTAIN;
        } else if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE,
            state.getWorkflowTrace())) {
            HandshakeMessage skeMsg = WorkflowTraceUtil
                .getFirstReceivedMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, state.getWorkflowTrace());
            if (skeMsg instanceof ECDHEServerKeyExchangeMessage) {
                ECDHEServerKeyExchangeMessage kex = (ECDHEServerKeyExchangeMessage) skeMsg;
                if (kex.getGroupType().getValue() == curveType.getValue()) {
                    return TestResults.TRUE;
                }
            }

        }
        return TestResults.FALSE;
    }

    private Config getBasicConfig() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
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

    private Map<NamedGroup, NamedGroupWitness> getTls13SupportedGroups() {
        Map<NamedGroup, NamedGroupWitness> namedGroupMap = new HashMap<>();
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
                    ignoresEcdsaGroupDisparity = TestResults.TRUE;
                    certificateGroup = null;
                }

                if (!toTestList.contains(certificateSigGroup) && certificateSigGroup != null) {
                    ignoresEcdsaGroupDisparity = TestResults.TRUE;
                    certificateSigGroup = null;
                }

                if (!toTestList.contains(selectedGroup)) {
                    LOGGER.warn("Server chose a group we did not offer:" + selectedGroup);
                    // TODO add to site report
                    break;
                }

                namedGroupMap.put(selectedGroup, new NamedGroupWitness(certificateGroup, null, certificateSigGroup,
                    context.getSelectedCipherSuite()));
                toTestList.remove(selectedGroup);
            }
        } while (context != null && !toTestList.isEmpty());
        return namedGroupMap;
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

    private void addGroupsFound(Map<NamedGroup, NamedGroupWitness> supportedMap,
        Map<NamedGroup, NamedGroupWitness> newlyFoundGroups, KeyExchangeAlgorithm keyExchangeAlgorithm) {

        for (NamedGroup group : newlyFoundGroups.keySet()) {
            NamedGroupWitness witness;
            if (supportedMap.containsKey(group)) {
                witness = supportedMap.get(group);
            } else {
                witness = new NamedGroupWitness();
                supportedMap.put(group, witness);
            }

            witness.getCipherSuites().addAll(newlyFoundGroups.get(group).getCipherSuites());
            switch (keyExchangeAlgorithm) {
                case ECDH_ECDSA:
                    witness.setEcdsaSigGroupStatic(newlyFoundGroups.get(group).getEcdsaSigGroupStatic());
                    break;
                case ECDHE_ECDSA:
                    witness.setEcdsaPkGroupEphemeral(newlyFoundGroups.get(group).getEcdsaPkGroupEphemeral());
                    witness.setEcdsaSigGroupEphemeral(newlyFoundGroups.get(group).getEcdsaSigGroupEphemeral());
            }
        }
    }

    private TestResult getGroupsDependOnCipherSuite(Map<NamedGroup, NamedGroupWitness> overallSupported) {
        Set<CipherSuite> joinedCurveCipherSuites = new HashSet();
        Set<CipherSuite> joinedFfdheCipherSuites = new HashSet();
        overallSupported.keySet().forEach(group -> {
            if (group.isCurve()) {
                joinedCurveCipherSuites.addAll(overallSupported.get(group).getCipherSuites());
            } else {
                joinedFfdheCipherSuites.addAll(overallSupported.get(group).getCipherSuites());
            }
        });

        boolean foundMismatch = overallSupported.keySet().stream().anyMatch(group -> {
            return (group.isCurve()
                && !overallSupported.get(group).getCipherSuites().containsAll(joinedCurveCipherSuites))
                || (!group.isCurve()
                    && !overallSupported.get(group).getCipherSuites().containsAll(joinedFfdheCipherSuites));
        });

        if (foundMismatch) {
            return TestResults.TRUE;
        }
        return TestResults.FALSE;
    }
}
