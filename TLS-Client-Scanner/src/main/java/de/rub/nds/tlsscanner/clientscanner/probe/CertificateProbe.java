/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.requirements.PropertyTrueRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceMutator;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class CertificateProbe extends TlsClientProbe {

    private Set<X509CertificateChain> clientCertificates = null;

    public CertificateProbe(ParallelExecutor parallelExecutor, ClientScannerConfig scannerConfig) {
        super(parallelExecutor, TlsProbeType.CERTIFICATE, scannerConfig);
        register(TlsAnalyzedProperty.CERTIFICATE_CHAINS);
    }

    @Override
    protected void executeTest() {
        clientCertificates = new HashSet<>();
        for (ClientCertificateType certType : getTestableCertTypes()) {
            Config config = getConfig(certType);
            if (config == null) {
                continue;
            }
            X509CertificateChain x509clientCertChain = getClientCertificateChain(config, certType);
            if (x509clientCertChain == null || x509clientCertChain.getCertificateList().isEmpty()) {
                continue;
            }
            if (isCertificateAlreadyIncluded(clientCertificates, x509clientCertChain)) {
                continue;
            }
            clientCertificates.add(x509clientCertChain);
        }
    }

    private List<ClientCertificateType> getTestableCertTypes() {
        List<ClientCertificateType> clientCertificateTypes = new LinkedList<>();
        clientCertificateTypes.add(ClientCertificateType.RSA_SIGN);
        clientCertificateTypes.add(ClientCertificateType.DSS_SIGN);
        clientCertificateTypes.add(ClientCertificateType.ECDSA_SIGN);
        clientCertificateTypes.add(ClientCertificateType.RSA_FIXED_DH);
        clientCertificateTypes.add(ClientCertificateType.DSS_FIXED_DH);
        clientCertificateTypes.add(ClientCertificateType.RSA_FIXED_ECDH);
        clientCertificateTypes.add(ClientCertificateType.ECDSA_FIXED_ECDH);
        return clientCertificateTypes;
    }

    private Config getConfig(ClientCertificateType clientCertType) {
        Config config = scannerConfig.createConfig();
        config.setClientAuthentication(true);
        List<CipherSuite> suitableCipherSuites =
                config.getDefaultServerSupportedCipherSuites().stream()
                        .filter(suite -> isCipherSuiteSuitableForCertType(suite, clientCertType))
                        .collect(Collectors.toList());
        if (suitableCipherSuites.isEmpty()) {
            return null;
        }
        config.setDefaultServerSupportedCipherSuites(suitableCipherSuites);
        config.setDefaultSelectedCipherSuite(suitableCipherSuites.get(0));
        return config;
    }

    private boolean isCipherSuiteSuitableForCertType(
            CipherSuite cipherSuite, ClientCertificateType clientCertType) {
        KeyExchangeAlgorithm keyExchangeAlgorithm =
                AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite);
        switch (clientCertType) {
            case RSA_SIGN:
                return keyExchangeAlgorithm == KeyExchangeAlgorithm.RSA
                        || keyExchangeAlgorithm == KeyExchangeAlgorithm.DHE_RSA
                        || keyExchangeAlgorithm == KeyExchangeAlgorithm.ECDHE_RSA;
            case DSS_SIGN:
                return keyExchangeAlgorithm == KeyExchangeAlgorithm.DHE_DSS;
            case ECDSA_SIGN:
                return keyExchangeAlgorithm == KeyExchangeAlgorithm.ECDHE_ECDSA;
            case RSA_FIXED_DH:
                return keyExchangeAlgorithm == KeyExchangeAlgorithm.DH_RSA;
            case DSS_FIXED_DH:
                return keyExchangeAlgorithm == KeyExchangeAlgorithm.DH_DSS;
            case RSA_FIXED_ECDH:
                return keyExchangeAlgorithm == KeyExchangeAlgorithm.ECDH_RSA;
            case ECDSA_FIXED_ECDH:
                return keyExchangeAlgorithm == KeyExchangeAlgorithm.ECDH_ECDSA;
            default:
                throw new UnsupportedOperationException(
                        "Client certificate type "
                                + clientCertType.name()
                                + " is not supported yet");
        }
    }

    private X509CertificateChain getClientCertificateChain(
            Config config, ClientCertificateType certType) {
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER);
        CertificateRequestMessage message = new CertificateRequestMessage(config);
        message.setClientCertificateTypesCount(Modifiable.explicit(1));
        message.setClientCertificateTypes(Modifiable.explicit(new byte[] {certType.getValue()}));
        WorkflowTraceMutator.replaceStaticSendingMessage(
                trace, HandshakeMessageType.CERTIFICATE_REQUEST, message);

        State state = new State(config, trace);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            return state.getTlsContext().getClientCertificateChain();
        } else {
            return null;
        }
    }

    private boolean isCertificateAlreadyIncluded(
            Set<X509CertificateChain> recordedCertificates, X509CertificateChain certificate) {
        return recordedCertificates.stream()
                .anyMatch(
                        currCertChain ->
                                currCertChain
                                        .getCertificateList()
                                        .containsAll(certificate.getCertificateList()));
    }

    @Override
    public void adjustConfig(ClientReport report) {}

    @Override
    protected void mergeData(ClientReport report) {
        if (clientCertificates != null) {
            put(TlsAnalyzedProperty.CERTIFICATE_CHAINS, new LinkedList<>(clientCertificates));
        }
    }

    @Override
    public Requirement<ClientReport> getRequirements() {
        return new PropertyTrueRequirement<>(TlsAnalyzedProperty.SUPPORTS_CCA);
    }
}
