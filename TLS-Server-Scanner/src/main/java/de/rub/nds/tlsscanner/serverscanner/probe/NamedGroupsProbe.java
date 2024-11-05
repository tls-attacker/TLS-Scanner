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
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.namedgroup.NamedGroupWitness;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class NamedGroupsProbe extends TlsServerProbe {

    private Set<CipherSuite> supportedCipherSuites;

    // curves used for ecdsa in key exchange
    private List<NamedGroup> ecdsaPkGroupsEphemeral;
    private List<NamedGroup> ecdsaPkGroupsTls13;

    // curves used for ecdsa certificate signatures
    private List<NamedGroup> ecdsaCertSigGroupsStatic;
    private List<NamedGroup> ecdsaCertSigGroupsEphemeral;
    private List<NamedGroup> ecdsaCertSigGroupsTls13;

    private Map<NamedGroup, NamedGroupWitness> namedGroupsMap;
    private Map<NamedGroup, NamedGroupWitness> namedGroupsMapTls13;

    private TestResult supportsExplicitPrime = TestResults.COULD_NOT_TEST;
    private TestResult supportsExplicitChar2 = TestResults.COULD_NOT_TEST;
    private TestResult groupsDependOnCipherSuite = TestResults.COULD_NOT_TEST;
    private TestResult ignoresEcdsaGroupDisparity = TestResults.COULD_NOT_TEST;

    public NamedGroupsProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.NAMED_GROUPS, configSelector);
        register(
                TlsAnalyzedProperty.SUPPORTS_EXPLICIT_PRIME_CURVE,
                TlsAnalyzedProperty.SUPPORTS_EXPLICIT_CHAR2_CURVE,
                TlsAnalyzedProperty.GROUPS_DEPEND_ON_CIPHER,
                TlsAnalyzedProperty.IGNORES_ECDSA_GROUP_DISPARITY,
                TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS,
                TlsAnalyzedProperty.SUPPORTED_TLS13_GROUPS,
                TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS_WITNESSES,
                TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS_WITNESSES_TLS13);
    }

    @Override
    protected void executeTest() {
        namedGroupsMap = new HashMap<>();
        ignoresEcdsaGroupDisparity = TestResults.FALSE;

        supportsExplicitPrime = TestResults.CANNOT_BE_TESTED;
        supportsExplicitChar2 = TestResults.CANNOT_BE_TESTED;
        if (configSelector.foundWorkingConfig()) {
            namedGroupsMap.putAll(
                    getSupportedNamedGroups(
                            getCipherSuiteByKeyExchange(KeyExchangeAlgorithm.DHE_RSA), false));
            namedGroupsMap.putAll(
                    getSupportedNamedGroups(
                            getCipherSuiteByKeyExchange(KeyExchangeAlgorithm.DHE_DSS), false));
            namedGroupsMap.putAll(
                    getSupportedNamedGroups(
                            getCipherSuiteByKeyExchange(KeyExchangeAlgorithm.DH_ANON), false));
            namedGroupsMap.putAll(
                    getSupportedNamedGroups(
                            getCipherSuiteByKeyExchange(
                                    KeyExchangeAlgorithm.ECDHE_RSA, KeyExchangeAlgorithm.ECDH_RSA),
                            true));
            namedGroupsMap.putAll(
                    getSupportedNamedCurvesEcdsa(
                            getCipherSuiteByKeyExchange(KeyExchangeAlgorithm.ECDHE_ECDSA),
                            ecdsaPkGroupsEphemeral,
                            ecdsaCertSigGroupsEphemeral));
            namedGroupsMap.putAll(
                    getSupportedNamedCurvesEcdsa(
                            getCipherSuiteByKeyExchange(KeyExchangeAlgorithm.ECDH_ECDSA),
                            null,
                            ecdsaCertSigGroupsStatic));
            supportsExplicitPrime = getExplicitCurveSupport(EllipticCurveType.EXPLICIT_PRIME);
            supportsExplicitChar2 = getExplicitCurveSupport(EllipticCurveType.EXPLICIT_CHAR2);
        }

        namedGroupsMapTls13 = new HashMap<>();
        if (configSelector.foundWorkingTls13Config()) {
            namedGroupsMapTls13 = getTls13SupportedGroups();
        }

        groupsDependOnCipherSuite = getGroupsDependOnCipherSuite(namedGroupsMap);
    }

    private Map<NamedGroup, NamedGroupWitness> getSupportedNamedGroups(
            List<CipherSuite> cipherSuites, boolean useCurves) {
        Map<NamedGroup, NamedGroupWitness> supportedNamedGroups = new HashMap<>();

        if (cipherSuites.isEmpty()) {
            return supportedNamedGroups;
        }

        Config tlsConfig = getBasicConfig();
        tlsConfig.setDefaultClientSupportedCipherSuites((cipherSuites));
        List<NamedGroup> toTestList =
                Arrays.asList(NamedGroup.values()).stream()
                        .filter(
                                group -> {
                                    if (useCurves) {
                                        return group.isCurve();
                                    } else {
                                        return group.isDhGroup();
                                    }
                                })
                        .collect(Collectors.toList());

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

                supportedNamedGroups.put(
                        selectedGroup, new NamedGroupWitness(context.getSelectedCipherSuite()));
                toTestList.remove(selectedGroup);
            }
        } while (context != null && !toTestList.isEmpty());
        return supportedNamedGroups;
    }

    private Map<NamedGroup, NamedGroupWitness> getSupportedNamedCurvesEcdsa(
            List<CipherSuite> cipherSuites, List<NamedGroup> pkGroups, List<NamedGroup> sigGroups) {
        HashMap<NamedGroup, NamedGroupWitness> namedCurveMap = new HashMap<>();

        if (cipherSuites.isEmpty()) {
            return namedCurveMap;
        }

        Config tlsConfig = getBasicConfig();
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites);
        List<NamedGroup> toTestList = new ArrayList<>(Arrays.asList(NamedGroup.values()));

        TlsContext context;
        NamedGroup selectedGroup = null;
        X509NamedCurve certificateGroup = null;
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
                certificateGroup = context.getServerX509Context().getSubjectNamedCurve();
                if (!toTestList.contains(selectedGroup)) {
                    LOGGER.debug("Server chose a Curve we did not offer!");
                    break;
                }
                if (cipherSuites.get(0).isEphemeral()) {
                    namedCurveMap.put(
                            selectedGroup,
                            new NamedGroupWitness(
                                    selectedGroup,
                                    certificateGroup,
                                    context.getSelectedCipherSuite()));
                } else {
                    namedCurveMap.put(
                            selectedGroup,
                            new NamedGroupWitness(
                                    null, certificateGroup, context.getSelectedCipherSuite()));
                }

                toTestList.remove(selectedGroup);
            }
        } while (context != null && !toTestList.isEmpty());
        return namedCurveMap;
    }

    private TlsContext testGroups(List<NamedGroup> groupList, Config tlsConfig) {
        tlsConfig.setDefaultClientNamedGroups(groupList);
        configSelector.repairConfig(tlsConfig);
        if (groupList.stream().anyMatch(NamedGroup::isDhGroup)) {
            // usually, we do not want this extension if no ecc cipher suites
            // are listed but it is required to test for listed FFDHE groups
            tlsConfig.setAddEllipticCurveExtension(true);
        }
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO)) {
            return state.getTlsContext();
        } else {
            LOGGER.debug(
                    "Did not receive a ServerHello, something went wrong or the Server has some intolerance");
            return null;
        }
    }

    private List<CipherSuite> getCipherSuiteByKeyExchange(KeyExchangeAlgorithm... algorithms) {
        List<CipherSuite> chosenCipherSuites = new LinkedList<>();
        List<KeyExchangeAlgorithm> algorithmList = Arrays.asList(algorithms);
        for (CipherSuite cipherSuite : supportedCipherSuites) {
            if (cipherSuite.isRealCipherSuite()
                    && !cipherSuite.isTls13()
                    && algorithmList.contains(
                            AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite))) {
                chosenCipherSuites.add(cipherSuite);
            }
        }
        return chosenCipherSuites;
    }

    private List<CipherSuite> getAllEcCipherSuites() {
        List<CipherSuite> suiteList = new LinkedList<>();
        for (CipherSuite suite : supportedCipherSuites) {
            if (suite.isRealCipherSuite()
                    && !suite.isTls13()
                    && AlgorithmResolver.getKeyExchangeAlgorithm(suite).isKeyExchangeEcdh()) {
                suiteList.add(suite);
            }
        }
        return suiteList;
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProbeRequirement<>(TlsProbeType.PROTOCOL_VERSION, TlsProbeType.CERTIFICATE);
    }

    @Override
    public void adjustConfig(ServerReport report) {
        ecdsaPkGroupsEphemeral = report.getEphemeralEcdsaPkgGroups();
        ecdsaPkGroupsTls13 = report.getTls13EcdsaPkgGroups();
        ecdsaCertSigGroupsStatic = report.getStaticEcdsaSigGroups();
        ecdsaCertSigGroupsEphemeral = report.getEphemeralEcdsaSigGroups();
        ecdsaCertSigGroupsTls13 = report.getTls13EcdsaSigGroups();
        supportedCipherSuites = report.getSupportedCipherSuites();
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
        configSelector.repairConfig(tlsConfig);
        State state = new State(tlsConfig);
        executeState(state);

        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), ProtocolMessageType.UNKNOWN)) {
            return TestResults.UNCERTAIN;
        } else if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.SERVER_KEY_EXCHANGE)) {
            HandshakeMessage skeMsg =
                    WorkflowTraceResultUtil.getFirstReceivedMessage(
                            state.getWorkflowTrace(), HandshakeMessageType.SERVER_KEY_EXCHANGE);
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
        Config tlsConfig = configSelector.getBaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
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
        X509NamedCurve certificateGroup = null;
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
                certificateGroup = context.getServerX509Context().getSubjectNamedCurve();

                if (!toTestList.contains(selectedGroup)) {
                    LOGGER.warn("Server chose a group we did not offer:" + selectedGroup);
                    // TODO add to site report
                    break;
                }

                namedGroupMap.put(
                        selectedGroup,
                        new NamedGroupWitness(
                                selectedGroup, certificateGroup, context.getSelectedCipherSuite()));
                toTestList.remove(selectedGroup);
            }
        } while (context != null && !toTestList.isEmpty());
        return namedGroupMap;
    }

    public TlsContext getTls13SupportedGroup(List<NamedGroup> groups) {
        Config tlsConfig = configSelector.getTls13BaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setDefaultClientNamedGroups(groups);
        tlsConfig.setDefaultClientKeyShareNamedGroups(groups);
        configSelector.repairConfig(tlsConfig);
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO)) {
            return state.getTlsContext();
        } else {
            LOGGER.debug("Did not receive ServerHello Message");
            LOGGER.debug(state.getWorkflowTrace().toString());
            return null;
        }
    }

    private TestResult getGroupsDependOnCipherSuite(
            Map<NamedGroup, NamedGroupWitness> overallSupported) {
        Set<CipherSuite> joinedCurveCipherSuites = new HashSet<>();
        Set<CipherSuite> joinedFfdheCipherSuites = new HashSet<>();
        overallSupported
                .keySet()
                .forEach(
                        group -> {
                            if (group.isCurve()) {
                                joinedCurveCipherSuites.addAll(
                                        overallSupported.get(group).getCipherSuites());
                            } else {
                                joinedFfdheCipherSuites.addAll(
                                        overallSupported.get(group).getCipherSuites());
                            }
                        });

        boolean foundMismatch =
                overallSupported.keySet().stream()
                        .anyMatch(
                                group -> {
                                    return (group.isCurve()
                                                    && !overallSupported
                                                            .get(group)
                                                            .getCipherSuites()
                                                            .containsAll(joinedCurveCipherSuites))
                                            || (!group.isCurve()
                                                    && !overallSupported
                                                            .get(group)
                                                            .getCipherSuites()
                                                            .containsAll(joinedFfdheCipherSuites));
                                });

        if (foundMismatch) {
            return TestResults.TRUE;
        }
        return TestResults.FALSE;
    }

    @Override
    protected void mergeData(ServerReport report) {
        LinkedList<NamedGroup> allGroups = new LinkedList<>();
        if (namedGroupsMap != null) {
            allGroups.addAll(namedGroupsMap.keySet());
        }
        LinkedList<NamedGroup> tls13Groups = new LinkedList<>();
        if (namedGroupsMapTls13 != null) {
            tls13Groups.addAll(namedGroupsMapTls13.keySet());
        }
        put(TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS, allGroups);
        put(TlsAnalyzedProperty.SUPPORTED_TLS13_GROUPS, tls13Groups);
        put(TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS_WITNESSES, namedGroupsMap);
        put(TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS_WITNESSES_TLS13, namedGroupsMapTls13);
        put(TlsAnalyzedProperty.SUPPORTS_EXPLICIT_PRIME_CURVE, supportsExplicitPrime);
        put(TlsAnalyzedProperty.SUPPORTS_EXPLICIT_CHAR2_CURVE, supportsExplicitChar2);
        put(TlsAnalyzedProperty.GROUPS_DEPEND_ON_CIPHER, groupsDependOnCipherSuite);
        put(TlsAnalyzedProperty.IGNORES_ECDSA_GROUP_DISPARITY, ignoresEcdsaGroupDisparity);
    }
}
