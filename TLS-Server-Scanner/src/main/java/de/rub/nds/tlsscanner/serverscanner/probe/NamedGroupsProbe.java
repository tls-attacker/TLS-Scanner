/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.MapResult;
import de.rub.nds.scanner.core.constants.SetResult;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
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
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.probe.namedgroup.NamedGroupWitness;
import de.rub.nds.tlsscanner.serverscanner.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class NamedGroupsProbe extends TlsProbe<ServerScannerConfig, ServerReport> {

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

    private TestResult supportsExplicitPrime;
    private TestResult supportsExplicitChar2;
    private TestResult groupsDependOnCipherSuite;
    private TestResult ignoresEcdsaGroupDisparity = TestResults.FALSE;

    public NamedGroupsProbe(ServerScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.NAMED_GROUPS, config);
        super.register(TlsAnalyzedProperty.SUPPORTS_EXPLICIT_PRIME_CURVE,
            TlsAnalyzedProperty.SUPPORTS_EXPLICIT_CHAR2_CURVE, TlsAnalyzedProperty.GROUPS_DEPEND_ON_CIPHER,
            TlsAnalyzedProperty.IGNORES_ECDSA_GROUP_DISPARITY, TlsAnalyzedProperty.LIST_SUPPORTED_NAMEDGROUPS,
            TlsAnalyzedProperty.LIST_SUPPORTED_TLS13_GROUPS, TlsAnalyzedProperty.MAP_SUPPORTED_NAMEDGROUPS_WITNESSES,
            TlsAnalyzedProperty.MAP_SUPPORTED_NAMEDGROUPS_WITNESSES_TLS13);
    }

    @Override
    public void executeTest() {
        this.namedGroupsMap = new HashMap<>();

        addGroupsFound(this.namedGroupsMap,
            getSupportedNamedGroups(getCipherSuiteByKeyExchange(KeyExchangeAlgorithm.DHE_RSA), false),
            KeyExchangeAlgorithm.DHE_RSA);
        addGroupsFound(this.namedGroupsMap,
            getSupportedNamedGroups(getCipherSuiteByKeyExchange(KeyExchangeAlgorithm.DHE_DSS), false),
            KeyExchangeAlgorithm.DHE_DSS);
        addGroupsFound(this.namedGroupsMap,
            getSupportedNamedGroups(getCipherSuiteByKeyExchange(KeyExchangeAlgorithm.DH_ANON), false),
            KeyExchangeAlgorithm.DH_ANON);

        addGroupsFound(this.namedGroupsMap,
            getSupportedNamedGroups(getCipherSuiteByKeyExchange(KeyExchangeAlgorithm.ECDH_ANON), true),
            KeyExchangeAlgorithm.ECDH_ANON);
        addGroupsFound(this.namedGroupsMap,
            getSupportedNamedGroups(
                getCipherSuiteByKeyExchange(KeyExchangeAlgorithm.ECDHE_RSA, KeyExchangeAlgorithm.ECDH_RSA), true),
            KeyExchangeAlgorithm.ECDHE_RSA);
        addGroupsFound(this.namedGroupsMap,
            getSupportedNamedCurvesEcdsa(getCipherSuiteByKeyExchange(KeyExchangeAlgorithm.ECDHE_ECDSA),
                this.ecdsaPkGroupsEphemeral, this.ecdsaCertSigGroupsEphemeral),
            KeyExchangeAlgorithm.ECDHE_ECDSA);
        addGroupsFound(this.namedGroupsMap,
            getSupportedNamedCurvesEcdsa(getCipherSuiteByKeyExchange(KeyExchangeAlgorithm.ECDH_ECDSA), null,
                this.ecdsaCertSigGroupsStatic),
            KeyExchangeAlgorithm.ECDH_ECDSA);
        this.supportsExplicitPrime = getExplicitCurveSupport(EllipticCurveType.EXPLICIT_PRIME);
        this.supportsExplicitChar2 = getExplicitCurveSupport(EllipticCurveType.EXPLICIT_CHAR2);
        this.namedGroupsMapTls13 = getTls13SupportedGroups();
        this.groupsDependOnCipherSuite = getGroupsDependOnCipherSuite(this.namedGroupsMap);
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
    protected Requirement getRequirements(ServerReport report) {
        return new ProbeRequirement(report).requireProbeTypes(TlsProbeType.PROTOCOL_VERSION, TlsProbeType.CERTIFICATE);
    }

    @SuppressWarnings("unchecked")
    @Override
    public void adjustConfig(ServerReport report) {
        TestResult ecdsaPkGroupsEphemeralResult =
            report.getResultMap().get(TlsAnalyzedProperty.LIST_EPHEMERAL_ECDSA_PKGROUPS.name());
        if (ecdsaPkGroupsEphemeralResult != null)
            ecdsaPkGroupsEphemeral = ((ListResult<NamedGroup>) ecdsaPkGroupsEphemeralResult).getList();
        TestResult ecdsaPkGroupsTls13Result =
            report.getResultMap().get(TlsAnalyzedProperty.LIST_TLS13_ECDSA_PKGROUPS.name());
        if (ecdsaPkGroupsTls13Result != null)
            ecdsaPkGroupsTls13 = ((ListResult<NamedGroup>) ecdsaPkGroupsTls13Result).getList();
        TestResult ecdsaCertSigGroupsStaticResult =
            report.getResultMap().get(TlsAnalyzedProperty.LIST_TLS13_ECDSA_PKGROUPS.name());
        if (ecdsaCertSigGroupsStaticResult != null)
            ecdsaCertSigGroupsStatic = ((ListResult<NamedGroup>) ecdsaCertSigGroupsStaticResult).getList();
        TestResult ecdsaCertSigGroupsEphemeralResult =
            report.getResultMap().get(TlsAnalyzedProperty.LIST_EPHEMERAL_ECDSA_SIGGROUPS.name());
        if (ecdsaCertSigGroupsEphemeralResult != null)
            ecdsaCertSigGroupsEphemeral = ((ListResult<NamedGroup>) ecdsaCertSigGroupsEphemeralResult).getList();
        TestResult ecdsaCertSigGroupsTls13Result =
            report.getResultMap().get(TlsAnalyzedProperty.LIST_TLS13_ECDSA_SIGGROUPS.name());
        if (ecdsaCertSigGroupsTls13Result != null)
            ecdsaCertSigGroupsTls13 = ((ListResult<NamedGroup>) ecdsaCertSigGroupsTls13Result).getList();
        TestResult supportedCipherSuitesResult = report.getResultMap().get(TlsAnalyzedProperty.SET_CIPHERSUITES.name());
        if (supportedCipherSuitesResult != null)
            supportedCipherSuites = ((SetResult<CipherSuite>) supportedCipherSuitesResult).getSet();
    }

    @Override
    public NamedGroupsProbe getCouldNotExecuteResult() {
        this.namedGroupsMap = this.namedGroupsMapTls13 = new HashMap<>();
        this.supportsExplicitPrime = this.supportsExplicitChar2 =
            this.groupsDependOnCipherSuite = this.ignoresEcdsaGroupDisparity = TestResults.COULD_NOT_TEST;
        return this;
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
                    break;
                default:
                    break;
            }
        }
    }

    private TestResult getGroupsDependOnCipherSuite(Map<NamedGroup, NamedGroupWitness> overallSupported) {
        Set<CipherSuite> joinedCurveCipherSuites = new HashSet<>();
        Set<CipherSuite> joinedFfdheCipherSuites = new HashSet<>();
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

    @Override
    protected void mergeData(ServerReport report) {
        LinkedList<NamedGroup> allGroups = new LinkedList<>();
        if (this.namedGroupsMap != null)
            allGroups.addAll(this.namedGroupsMap.keySet());
        LinkedList<NamedGroup> tls13Groups = new LinkedList<>();
        if (this.namedGroupsMapTls13 != null)
            tls13Groups.addAll(this.namedGroupsMapTls13.keySet());
        super.put(TlsAnalyzedProperty.LIST_SUPPORTED_NAMEDGROUPS,
            new ListResult<NamedGroup>(allGroups, "SUPPORTED_NAMEDGROUPS"));
        super.put(TlsAnalyzedProperty.LIST_SUPPORTED_TLS13_GROUPS,
            new ListResult<NamedGroup>(tls13Groups, "SUPPORTED_TLS13_GROUPS"));
        super.put(TlsAnalyzedProperty.MAP_SUPPORTED_NAMEDGROUPS_WITNESSES,
            new MapResult<NamedGroup, NamedGroupWitness>(this.namedGroupsMap, "NAMEDGROUPS_WITNESSES"));
        super.put(TlsAnalyzedProperty.MAP_SUPPORTED_NAMEDGROUPS_WITNESSES_TLS13,
            new MapResult<NamedGroup, NamedGroupWitness>(this.namedGroupsMapTls13, "NAMEDGROUPS_WITNESSES_TLS13"));
        super.put(TlsAnalyzedProperty.SUPPORTS_EXPLICIT_PRIME_CURVE, this.supportsExplicitPrime);
        super.put(TlsAnalyzedProperty.SUPPORTS_EXPLICIT_CHAR2_CURVE, this.supportsExplicitChar2);
        super.put(TlsAnalyzedProperty.GROUPS_DEPEND_ON_CIPHER, this.groupsDependOnCipherSuite);
        super.put(TlsAnalyzedProperty.IGNORES_ECDSA_GROUP_DISPARITY, this.ignoresEcdsaGroupDisparity);
    }
}
