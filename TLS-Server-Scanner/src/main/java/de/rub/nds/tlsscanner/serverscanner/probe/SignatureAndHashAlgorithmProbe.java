/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolVersionRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.function.Predicate;

public class SignatureAndHashAlgorithmProbe extends TlsServerProbe {

    private List<ProtocolVersion> versions;

    private List<SignatureAndHashAlgorithm> signatureAndHashAlgorithmListSke;
    private List<SignatureAndHashAlgorithm> signatureAndHashAlgorithmListTls13;

    public SignatureAndHashAlgorithmProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.SIGNATURE_AND_HASH, configSelector);
        register(
                TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_SKE,
                TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_TLS13);
    }

    @Override
    protected void executeTest() {
        Set<SignatureAndHashAlgorithm> supportedSke = new HashSet<>();
        Set<SignatureAndHashAlgorithm> supportedTls13 = new HashSet<>();
        for (ProtocolVersion version : versions) {
            if (version.isTLS13()) {
                supportedTls13.addAll(testForVersion(version, CipherSuite::isTLS13));
            } else {
                supportedSke.addAll(
                        testForVersion(version, suite -> !suite.isTLS13() && suite.isEphemeral()));
            }
        }
        signatureAndHashAlgorithmListSke = new ArrayList<>(supportedSke);
        signatureAndHashAlgorithmListTls13 = new ArrayList<>(supportedTls13);
    }

    private Set<SignatureAndHashAlgorithm> testForVersion(
            ProtocolVersion version, Predicate<CipherSuite> predicate) {
        Set<SignatureAndHashAlgorithm> found = new HashSet<>();
        Set<List<SignatureAndHashAlgorithm>> tested = new HashSet<>();

        Config tlsConfig =
                version.isTLS13()
                        ? configSelector.getTls13BaseConfig()
                        : configSelector.getBaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setHighestProtocolVersion(version);
        tlsConfig.getDefaultClientSupportedCipherSuites().removeIf(predicate.negate());
        configSelector.repairConfig(tlsConfig);

        Queue<List<SignatureAndHashAlgorithm>> testQueue = new LinkedList<>();
        testQueue.add(
                version.isTLS13()
                        ? SignatureAndHashAlgorithm.getTls13SignatureAndHashAlgorithms()
                        : Arrays.asList(SignatureAndHashAlgorithm.values()));

        State state;

        while (!testQueue.isEmpty()) {
            List<SignatureAndHashAlgorithm> testSet = testQueue.poll();
            if (tested.contains(testSet)) {
                continue;
            }
            tested.add(testSet);

            state = testAlgorithms(testSet, tlsConfig);
            if (state != null) {
                SignatureAndHashAlgorithm selected =
                        version.isTLS13()
                                ? getSelectedSignatureAndHashAlgorithmCV(state)
                                : getSelectedSignatureAndHashAlgorithmSke(state);
                if (selected == null) {
                    continue;
                }
                if (!testSet.contains(selected)) {
                    found.add(selected);
                    break;
                }
                // if any new algorithms were found
                if (!found.contains(selected)) {
                    // move selected to end
                    if (testSet.contains(selected)) {
                        List<SignatureAndHashAlgorithm> selectedToEnd = new ArrayList<>(testSet);
                        selectedToEnd.remove(selected);
                        selectedToEnd.add(selected);
                        testQueue.add(selectedToEnd);
                    }
                    // remove possible combinations of selected
                    List<SignatureAndHashAlgorithm> newTestSet = new ArrayList<>(testSet);
                    newTestSet.remove(selected);
                    testQueue.add(newTestSet);
                }
                found.add(selected);
            }
        }
        return found;
    }

    private SignatureAndHashAlgorithm getSelectedSignatureAndHashAlgorithmCV(State state) {
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.CERTIFICATE_VERIFY)) {
            HandshakeMessage message =
                    WorkflowTraceResultUtil.getLastReceivedMessage(
                            state.getWorkflowTrace(), HandshakeMessageType.CERTIFICATE_VERIFY);
            if (message instanceof CertificateVerifyMessage) {
                CertificateVerifyMessage msg = (CertificateVerifyMessage) message;
                ModifiableByteArray algByte = msg.getSignatureHashAlgorithm();
                if (algByte != null) {
                    return SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(
                            algByte.getValue());
                }
            }
        }
        return null;
    }

    private SignatureAndHashAlgorithm getSelectedSignatureAndHashAlgorithmSke(State state) {
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.SERVER_KEY_EXCHANGE)) {
            HandshakeMessage message =
                    WorkflowTraceResultUtil.getLastReceivedMessage(
                            state.getWorkflowTrace(), HandshakeMessageType.SERVER_KEY_EXCHANGE);
            if (message instanceof ServerKeyExchangeMessage) {
                ServerKeyExchangeMessage msg = (ServerKeyExchangeMessage) message;
                ModifiableByteArray algByte = msg.getSignatureAndHashAlgorithm();
                if (algByte != null) {
                    return SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(
                            algByte.getValue());
                }
            }
        }
        return null;
    }

    private State testAlgorithms(List<SignatureAndHashAlgorithm> algorithms, Config config) {
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(algorithms);
        State state = new State(config);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            return state;
        } else {
            LOGGER.debug(
                    "Did not receive a ServerHello, something went wrong or the Server has some intolerance");
            return null;
        }
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProbeRequirement<ServerReport>(TlsProbeType.PROTOCOL_VERSION)
                .and(
                        new ProtocolVersionRequirement<ServerReport>(ProtocolVersion.TLS12)
                                .or(new ProtocolVersionRequirement<>(ProtocolVersion.TLS13))
                                .or(new ProtocolVersionRequirement<>(ProtocolVersion.DTLS12)));
    }

    @Override
    public void adjustConfig(ServerReport report) {
        this.versions = new ArrayList<>();
        for (ProtocolVersion version : report.getSupportedProtocolVersions()) {
            if (version.equals(ProtocolVersion.DTLS12)
                    || version.equals(ProtocolVersion.TLS12)
                    || version.isTLS13()) {
                versions.add(version);
            }
        }
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(
                TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_SKE,
                signatureAndHashAlgorithmListSke);
        put(
                TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_TLS13,
                signatureAndHashAlgorithmListTls13);
    }
}
