/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAlgorithmsCertExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolVersionRequirement;
import java.util.*;
import java.util.function.Function;
import java.util.function.Predicate;

public class SignatureAndHashAlgorithmProbe extends TlsClientProbe {

    private List<ProtocolVersion> versions;

    private List<SignatureAndHashAlgorithm> signatureAndHashAlgorithmListSke;
    private List<SignatureAndHashAlgorithm> signatureAndHashAlgorithmListTls13;
    private List<SignatureAndHashAlgorithm> signatureAndHashAlgorithmCertList;

    private boolean errorOnTest;

    public SignatureAndHashAlgorithmProbe(
            ParallelExecutor parallelExecutor, ClientScannerConfig scannerConfig) {
        super(parallelExecutor, TlsProbeType.SIGNATURE_AND_HASH, scannerConfig);
        register(
                TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_SKE,
                TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_TLS13,
                TlsAnalyzedProperty.SUPPORTED_CERT_SIGNATURE_ALGORITHMS);
    }

    @Override
    protected void executeTest() {
        Set<SignatureAndHashAlgorithm> supportedSke = new HashSet<>();
        Set<SignatureAndHashAlgorithm> supportedTls13 = new HashSet<>();
        Set<SignatureAndHashAlgorithm> supportedCert = new HashSet<>();
        for (ProtocolVersion version : versions) {
            Set<SignatureAndHashAlgorithm> temp = new HashSet<>();
            Set<SignatureAndHashAlgorithm> tempCert = new HashSet<>();
            if (version.isTLS13()) {
                temp.addAll(
                        testForVersion(
                                version,
                                CipherSuite::isTLS13,
                                this::getOfferedSignatureAndHashAlgorithms));
                supportedTls13.addAll(temp);
                tempCert.addAll(
                        testForVersion(
                                version,
                                CipherSuite::isTLS13,
                                this::getOfferedSignatureAndHashAlgorithmsCert));

            } else {
                temp.addAll(
                        testForVersion(
                                version,
                                suite -> !suite.isTLS13() && suite.isEphemeral(),
                                this::getOfferedSignatureAndHashAlgorithms));
                supportedSke.addAll(temp);
                tempCert.addAll(
                        testForVersion(
                                version,
                                suite -> !suite.isTLS13() && suite.isEphemeral(),
                                this::getOfferedSignatureAndHashAlgorithmsCert));
            }
            supportedCert.addAll(tempCert.isEmpty() ? temp : tempCert);
        }
        signatureAndHashAlgorithmListSke = new ArrayList<>(supportedSke);
        signatureAndHashAlgorithmListTls13 = new ArrayList<>(supportedTls13);
        signatureAndHashAlgorithmCertList = new ArrayList<>(supportedCert);
    }

    private Set<SignatureAndHashAlgorithm> testForVersion(
            ProtocolVersion version,
            Predicate<CipherSuite> predicate,
            Function<State, List<SignatureAndHashAlgorithm>> testFunction) {

        Config tlsConfig = version.isTLS13() ? getTls13Config() : getBaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setHighestProtocolVersion(version);
        tlsConfig.getDefaultServerSupportedCipherSuites().removeIf(predicate.negate());
        // configSelector.repairConfig(tlsConfig); TODO

        State state =
                testAlgorithms(
                        version.isTLS13()
                                ? SignatureAndHashAlgorithm.getTls13SignatureAndHashAlgorithms()
                                : Arrays.asList(SignatureAndHashAlgorithm.values()),
                        tlsConfig);
        errorOnTest = state == null;
        if (errorOnTest) {
            return new HashSet<>();
        }
        return new HashSet<>(testFunction.apply(state));
    }

    private Config getBaseConfig() {
        Config config = scannerConfig.createConfig();
        config.setStopReceivingAfterFatal(true);
        config.setStopActionsAfterFatal(true);
        return config;
    }

    private Config getTls13Config() {
        Config config = getBaseConfig();
        config.setAddRenegotiationInfoExtension(false);
        config.setAddECPointFormatExtension(false);
        config.setAddEllipticCurveExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);
        return config;
    }

    private List<SignatureAndHashAlgorithm> getOfferedSignatureAndHashAlgorithmsCert(State state) {
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.CLIENT_HELLO)) {
            HandshakeMessage message =
                    WorkflowTraceResultUtil.getLastReceivedMessage(
                            state.getWorkflowTrace(), HandshakeMessageType.CLIENT_HELLO);
            if (message instanceof ClientHelloMessage) {
                ClientHelloMessage msg = (ClientHelloMessage) message;
                SignatureAlgorithmsCertExtensionMessage ext =
                        msg.getExtension(SignatureAlgorithmsCertExtensionMessage.class);
                if (ext == null) {
                    return new ArrayList<>();
                }
                return SignatureAndHashAlgorithm.getSignatureAndHashAlgorithms(
                        ext.getSignatureAndHashAlgorithms().getValue());
            }
        }
        return new ArrayList<>();
    }

    private List<SignatureAndHashAlgorithm> getOfferedSignatureAndHashAlgorithms(State state) {
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.CLIENT_HELLO)) {
            HandshakeMessage message =
                    WorkflowTraceResultUtil.getLastReceivedMessage(
                            state.getWorkflowTrace(), HandshakeMessageType.CLIENT_HELLO);
            if (message instanceof ClientHelloMessage) {
                ClientHelloMessage msg = (ClientHelloMessage) message;
                SignatureAndHashAlgorithmsExtensionMessage ext =
                        msg.getExtension(SignatureAndHashAlgorithmsExtensionMessage.class);
                if (ext == null) {
                    return new ArrayList<>();
                }
                return SignatureAndHashAlgorithm.getSignatureAndHashAlgorithms(
                        ext.getSignatureAndHashAlgorithms().getValue());
            }
        }
        return new ArrayList<>();
    }

    private State testAlgorithms(List<SignatureAndHashAlgorithm> algorithms, Config config) {
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(algorithms);
        State state = new State(config);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            return state;
        } else {
            LOGGER.debug("Something went wrong or the Client has some intolerance");
            return null;
        }
    }

    @Override
    public Requirement<ClientReport> getRequirements() {
        return new ProbeRequirement<ClientReport>(TlsProbeType.PROTOCOL_VERSION)
                .and(
                        new ProtocolVersionRequirement<ClientReport>(ProtocolVersion.TLS12)
                                .or(new ProtocolVersionRequirement<>(ProtocolVersion.TLS13))
                                .or(new ProtocolVersionRequirement<>(ProtocolVersion.DTLS12)));
    }

    @Override
    public void adjustConfig(ClientReport report) {
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
    protected void mergeData(ClientReport report) {
        if (errorOnTest) {
            setPropertiesToCouldNotTest();
            return;
        }
        put(
                TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_SKE,
                signatureAndHashAlgorithmListSke);
        put(
                TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_TLS13,
                signatureAndHashAlgorithmListTls13);
        put(
                TlsAnalyzedProperty.SUPPORTED_CERT_SIGNATURE_ALGORITHMS,
                signatureAndHashAlgorithmCertList);
    }
}
