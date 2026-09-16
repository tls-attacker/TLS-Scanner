/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.modifiablevariable.util.ComparableByteArray;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.protocol.constants.MlKemParameters;
import de.rub.nds.protocol.constants.PointFormat;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.ec.PointFormatter;
import de.rub.nds.protocol.crypto.ec.RFC7748Curve;
import de.rub.nds.protocol.crypto.kem.MlKemCalculator;
import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.PropertyTrueRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.FaultListResult;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceMutator;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.point.InvalidCurvePoint;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.point.TwistedCurvePoint;
import de.rub.nds.tlsscanner.serverscanner.probe.mlkem.MalformedEncapsulationKey;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/** Evaluates the details of the server's ML-KEM support */
public class MlKemProbe extends TlsServerProbe {

    private List<NamedGroup> supportedHybridMlKemGroups = new LinkedList<>();
    private List<NamedGroup> supportedPureMlKemGroups = new LinkedList<>();

    private List<NamedGroup> groupsWithSharedSecretReuse = new LinkedList<>();
    private List<NamedGroup> groupsWithMissingEcValidation = new LinkedList<>();
    private List<NamedGroup> groupsWithMissingEncapKeyLengthValidation = new LinkedList<>();
    private List<NamedGroup> groupsWithMissingEncapKeyPolynomialValidation = new LinkedList<>();
    private Map<NamedGroup, List<byte[]>> observedEcPublicKeys = new HashMap<>();
    private Map<NamedGroup, List<MalformedEncapsulationKey>> mlkemGroupMalformedKeys =
            new HashMap<>();

    public MlKemProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.ML_KEM, configSelector);
        register(
                TlsAnalyzedProperty.ML_KEM_SHARED_SECRET_REUSE_GROUPS,
                TlsAnalyzedProperty.ML_KEM_HYBRID_ECC_MISSING_VALIDATION_GROUPS,
                TlsAnalyzedProperty.ML_KEM_HYBRID_STATIC_ECC_PUBLIC_KEY_GROUPS,
                TlsAnalyzedProperty.ML_KEM_ENCAPSULATION_KEY_LENGTH_MISSING_VALIDATION_GROUPS,
                TlsAnalyzedProperty.ML_KEM_ENCAPSULATION_KEY_POLYNOMIAL_MISSING_VALIDATION_GROUPS);
    }

    @Override
    protected void executeTest() {
        List<NamedGroup> allMlKemGroups =
                Stream.concat(
                                supportedHybridMlKemGroups.stream(),
                                supportedPureMlKemGroups.stream())
                        .toList();
        evaluateEncapsulationKeyLengthValidation(allMlKemGroups);
        evaluateEncapsulationKeyPolynomialValidation(allMlKemGroups);
        evaluateEcPublicKeyValidation(supportedHybridMlKemGroups);
        evaluateSharedSecretSelection(supportedHybridMlKemGroups);
        evaluateSharedSecretSelection(supportedPureMlKemGroups);
    }

    private void evaluateSharedSecretSelection(List<NamedGroup> toTest) {
        for (NamedGroup group : toTest) {
            if (reusesSharedSecretForGroup(group)) {
                groupsWithSharedSecretReuse.add(group);
            }
        }
    }

    private void evaluateEcPublicKeyValidation(List<NamedGroup> toTest) {
        for (NamedGroup group : toTest) {
            if (acceptsMalformedEcPublicKey(group)) {
                groupsWithMissingEcValidation.add(group);
            }
        }
    }

    private void evaluateEncapsulationKeyLengthValidation(List<NamedGroup> toTest) {
        for (NamedGroup group : toTest) {
            if (acceptsInvalidMlkemLength(group)) {
                groupsWithMissingEncapKeyLengthValidation.add(group);
            }
        }
    }

    private void evaluateEncapsulationKeyPolynomialValidation(List<NamedGroup> toTest) {
        for (NamedGroup group : toTest) {
            if (acceptsMalformedEncapsulationKey(group)) {
                groupsWithMissingEncapKeyPolynomialValidation.add(group);
            }
        }
    }

    private boolean reusesSharedSecretForGroup(NamedGroup group) {
        Config config = getConfigForGroup(group);
        State firstState = new State(config);
        executeState(firstState);
        if (group.isHybridPQGroup()) {
            observedEcPublicKeys.get(group).add(extractReceivedEcPublicKey(firstState));
        }
        if (receivedRealServerHello(firstState)) {
            State secondState = new State(config);
            executeState(secondState);
            if (group.isHybridPQGroup()) {
                observedEcPublicKeys.get(group).add(extractReceivedEcPublicKey(secondState));
            }
            if (receivedRealServerHello(secondState)) {
                return identicalKeySharesSent(firstState, secondState);
            }
        }
        LOGGER.warn(
                "Could not evaluate freshness of ML-KEM shared secret. Server did not issue two ServerHello messages carrying key shares.");
        return false;
    }

    private boolean acceptsInvalidMlkemLength(NamedGroup group) {
        Config config = getConfigForGroup(group);
        State state = new State(config);
        WorkflowTraceMutator.replaceReceivingMessage(
                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO, new AlertMessage());
        KeyShareEntry ksEntry = getSendingKeyShareEntry(state);
        byte[] offendingEncKey =
                MlKemCalculator.generateKeyPair(getNonMatchingParameters(group), new BadRandom())
                        .getRight()
                        .getEncapsulationKey();
        ksEntry.setMlKemPublicKey(Modifiable.explicit(offendingEncKey));
        executeState(state);
        return receivedRealServerHello(state);
    }

    private boolean acceptsMalformedEncapsulationKey(NamedGroup group) {
        for (MalformedEncapsulationKey malformedKey :
                mlkemGroupMalformedKeys.get(group.getAnyInvolvedPqGroup())) {
            if (acceptsEncapsulationKey(group, malformedKey.getEncapsulationKey())) {
                LOGGER.debug(
                        "Server accepted encapsulation key of type {} for group {}",
                        malformedKey.getType(),
                        group);
                return true;
            }
        }
        return false;
    }

    private boolean acceptsEncapsulationKey(NamedGroup group, byte[] encapsulationKey) {
        Config config = getConfigForGroup(group);
        State state = new State(config);
        // invalid key share should always terminate the handshake
        WorkflowTraceMutator.replaceReceivingMessage(
                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO, new AlertMessage());
        KeyShareEntry ksEntry = getSendingKeyShareEntry(state);
        ksEntry.setMlKemPublicKey(Modifiable.explicit(encapsulationKey));
        executeState(state);
        return receivedRealServerHello(state);
    }

    private boolean receivedRealServerHello(State state) {
        if (!WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO)) {
            return false;
        }
        ServerHelloMessage sh =
                state.getWorkflowTrace().getFirstReceivedMessage(ServerHelloMessage.class);
        return !sh.isHelloRetryRequest();
    }

    private MlKemParameters getNonMatchingParameters(NamedGroup mlKemGroup) {
        if (!mlKemGroup.isMlKemGroup()) {
            throw new UnsupportedOperationException(
                    "Unable to yield parameters for unsupported group type " + mlKemGroup.name());
        }
        // Supply a key share that is valicd except for the parameter length
        if (mlKemGroup.getAnyInvolvedPqGroup() != NamedGroup.MLKEM512) {
            return (MlKemParameters) NamedGroup.MLKEM512.getAsymmetricParameters();
        } else {
            return (MlKemParameters) NamedGroup.MLKEM768.getAsymmetricParameters();
        }
    }

    private Config getConfigForGroup(NamedGroup group) {
        Config config = configSelector.getTls13BaseConfig();
        configSelector.repairConfig(config);
        config.setDefaultClientNamedGroups(group);
        config.setDefaultClientKeyShareNamedGroups(group);
        config.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        return config;
    }

    private boolean acceptsMalformedEcPublicKey(NamedGroup group) {
        Config config = getConfigForGroup(group);
        State state = new State(config);
        // invalid key share should always terminate the handshake
        WorkflowTraceMutator.replaceReceivingMessage(
                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO, new AlertMessage());
        manipulateEcKeySharePartForGroup(group.getHybridPostQuantumClassicNamedGroup(), state);
        executeState(state);
        return receivedRealServerHello(state);
    }

    private byte[] extractReceivedEcPublicKey(State state) {
        ServerHelloMessage sh =
                state.getWorkflowTrace().getFirstReceivedMessage(ServerHelloMessage.class);
        if (sh != null) {
            KeyShareExtensionMessage ksExtensions = sh.getExtension(KeyShareExtensionMessage.class);
            // ensure this was not an HRR key share extension containing no public key
            if (ksExtensions != null && ksExtensions.getExtensionLength().getValue() > 2) {
                return ksExtensions.getKeyShareList().get(0).getPublicKey().getValue();
            }
        }
        return null;
    }

    private void manipulateEcKeySharePartForGroup(NamedGroup group, State state) {
        Point invalidPoint;
        byte[] maliciousPublicKey;
        if (group == NamedGroup.ECDH_X25519) {
            invalidPoint = TwistedCurvePoint.smallOrder(group).getPoint();
            // ensure correct endianness for X25519
            RFC7748Curve curve = (RFC7748Curve) group.getGroupParameters().getGroup();
            maliciousPublicKey = curve.encodeCoordinate(invalidPoint.getFieldX().getData());
        } else {
            invalidPoint = InvalidCurvePoint.smallOrder(group).getPoint();
            maliciousPublicKey =
                    PointFormatter.formatToByteArray(
                            group.getGroupParameters(), invalidPoint, PointFormat.UNCOMPRESSED);
        }
        KeyShareEntry ksEntry = getSendingKeyShareEntry(state);
        ksEntry.setDhPublicKey(Modifiable.explicit(maliciousPublicKey));
    }

    private boolean identicalKeySharesSent(State state1, State state2) {
        KeyShareEntry entry1 = getReceivedKeyShareEntry(state1);
        KeyShareEntry entry2 = getReceivedKeyShareEntry(state2);

        return Arrays.equals(
                entry1.getMlKemCiphertext().getValue(), entry2.getMlKemCiphertext().getValue());
    }

    private KeyShareEntry getReceivedKeyShareEntry(State state) {
        ServerHelloMessage serverHello =
                (ServerHelloMessage)
                        WorkflowTraceResultUtil.getFirstReceivedMessage(
                                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO);
        KeyShareExtensionMessage ksExtension =
                serverHello.getExtension(KeyShareExtensionMessage.class);
        return ksExtension.getKeyShareList().get(0);
    }

    private KeyShareEntry getSendingKeyShareEntry(State state) {
        ClientHelloMessage ch =
                (ClientHelloMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                state.getWorkflowTrace(), HandshakeMessageType.CLIENT_HELLO);
        return ch.getExtension(KeyShareExtensionMessage.class).getKeyShareList().get(0);
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProbeRequirement<ServerReport>(TlsProbeType.NAMED_GROUPS)
                .and(new PropertyTrueRequirement<>(TlsAnalyzedProperty.SUPPORTS_MLKEM));
    }

    @Override
    public void adjustConfig(ServerReport report) {
        List<NamedGroup> tls13groups =
                report.getListResult(TlsAnalyzedProperty.SUPPORTED_TLS13_GROUPS, NamedGroup.class)
                        .getList();
        supportedHybridMlKemGroups =
                tls13groups.stream()
                        .filter(group -> group.isMlKemGroup() && group.isHybridPQGroup())
                        .toList();
        supportedPureMlKemGroups =
                tls13groups.stream()
                        .filter(group -> group.isMlKemGroup() && group.isPQGroup())
                        .toList();
        supportedHybridMlKemGroups.forEach(
                group -> observedEcPublicKeys.put(group, new LinkedList<>()));
        Set<NamedGroup> uniqueMlKemGroups = new HashSet<>();
        supportedHybridMlKemGroups.stream()
                .map(NamedGroup::getAnyInvolvedPqGroup)
                .forEach(group -> uniqueMlKemGroups.add(group));
        uniqueMlKemGroups.addAll(supportedPureMlKemGroups);
        uniqueMlKemGroups.forEach(
                group ->
                        mlkemGroupMalformedKeys.put(
                                group, MalformedEncapsulationKey.getAll(group)));
    }

    @Override
    protected void mergeData(ServerReport report) {
        TestResult eccValidationResult =
                resultIfEvaluated(
                        TlsAnalyzedProperty.ML_KEM_HYBRID_ECC_MISSING_VALIDATION_GROUPS,
                        groupsWithMissingEcValidation,
                        supportedHybridMlKemGroups);
        TestResult mlKemEncapKeyLengthValidationResult =
                new FaultListResult<>(
                        TlsAnalyzedProperty
                                .ML_KEM_ENCAPSULATION_KEY_LENGTH_MISSING_VALIDATION_GROUPS,
                        groupsWithMissingEncapKeyLengthValidation);
        TestResult mlKemEncapKeyPolynomialValidationResult =
                new FaultListResult<>(
                        TlsAnalyzedProperty
                                .ML_KEM_ENCAPSULATION_KEY_POLYNOMIAL_MISSING_VALIDATION_GROUPS,
                        groupsWithMissingEncapKeyPolynomialValidation);

        observedEcPublicKeys.values().forEach(publicKeys -> publicKeys.removeIf(Objects::isNull));
        List<NamedGroup> groupsWithPublicKeyReuse = new LinkedList<>();
        for (NamedGroup group : observedEcPublicKeys.keySet()) {
            List<byte[]> observedForGroup = observedEcPublicKeys.get(group);
            // byte[] does not implement equals(), hence we compare the contents explicitly
            Set<ComparableByteArray> uniqueKeyShares =
                    observedForGroup.stream()
                            .map(ComparableByteArray::new)
                            .collect(Collectors.toSet());
            if (uniqueKeyShares.size() < observedForGroup.size()) {
                groupsWithPublicKeyReuse.add(group);
            }
        }
        TestResult eccStaticKeysResult =
                resultIfEvaluated(
                        TlsAnalyzedProperty.ML_KEM_HYBRID_STATIC_ECC_PUBLIC_KEY_GROUPS,
                        groupsWithPublicKeyReuse,
                        supportedHybridMlKemGroups);

        put(TlsAnalyzedProperty.ML_KEM_HYBRID_ECC_MISSING_VALIDATION_GROUPS, eccValidationResult);
        put(
                TlsAnalyzedProperty.ML_KEM_SHARED_SECRET_REUSE_GROUPS,
                new FaultListResult<>(
                        TlsAnalyzedProperty.ML_KEM_SHARED_SECRET_REUSE_GROUPS,
                        groupsWithSharedSecretReuse));
        put(TlsAnalyzedProperty.ML_KEM_HYBRID_STATIC_ECC_PUBLIC_KEY_GROUPS, eccStaticKeysResult);
        put(
                TlsAnalyzedProperty.ML_KEM_ENCAPSULATION_KEY_LENGTH_MISSING_VALIDATION_GROUPS,
                mlKemEncapKeyLengthValidationResult);
        put(
                TlsAnalyzedProperty.ML_KEM_ENCAPSULATION_KEY_POLYNOMIAL_MISSING_VALIDATION_GROUPS,
                mlKemEncapKeyPolynomialValidationResult);
    }

    private FaultListResult<NamedGroup> resultIfEvaluated(
            TlsAnalyzedProperty resultProperty,
            List<NamedGroup> resultList,
            List<NamedGroup> dependentList) {
        if (dependentList.isEmpty()) {
            return new FaultListResult<>(resultProperty, TestResults.CANNOT_BE_TESTED);
        } else {
            return new FaultListResult<>(resultProperty, resultList);
        }
    }
}
