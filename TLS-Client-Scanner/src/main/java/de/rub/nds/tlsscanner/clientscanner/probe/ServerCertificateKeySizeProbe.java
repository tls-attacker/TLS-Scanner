/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.certificate.CertificateByteChooser;
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.OrRequirement;
import de.rub.nds.tlsscanner.core.probe.requirements.PropertyRequirement;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class ServerCertificateKeySizeProbe
        extends TlsClientProbe<ClientScannerConfig, ClientReport> {

    private TestResult enforcesMinimumKeySizeRSA = TestResults.COULD_NOT_TEST;
    private TestResult enforcesMinimumKeySizeDSS = TestResults.COULD_NOT_TEST;
    private TestResult enforcesMinimumKeySizeDH = TestResults.COULD_NOT_TEST;

    private List<CertificateKeyPair> rsaCertKeyPairs = new LinkedList<>();
    private List<CertificateKeyPair> dssCertKeyPairs = new LinkedList<>();
    private List<CertificateKeyPair> dhCertKeyPairs = new LinkedList<>();

    private boolean testRSA, testDSS, testDH = false;
    private int minimumRSAKeySize, minimumDSSKeySize, minimumDHKeySize;

    private List<CipherSuite> clientAdvertisedCipherSuites;

    private int ourLargestRSAKeySize, ourLargestDSSKeySize, ourLargestDHKeySize;
    private int ourSmallestRSAKeySize = Integer.MAX_VALUE;
    private int ourSmallestDSSKeySize = Integer.MAX_VALUE;
    private int ourSmallestDHKeySize = Integer.MAX_VALUE;

    public ServerCertificateKeySizeProbe(
            ParallelExecutor parallelExecutor, ClientScannerConfig scannerConfig) {
        super(parallelExecutor, TlsProbeType.SERVER_CERTIFICATE_MINIMUM_KEY_SIZE, scannerConfig);
        register(
                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_DSS,
                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_RSA,
                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_DH);
    }

    @Override
    protected void mergeData(ClientReport report) {
        put(TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_RSA, enforcesMinimumKeySizeRSA);
        put(TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_DSS, enforcesMinimumKeySizeDSS);
        put(TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_DH, enforcesMinimumKeySizeDH);

        report.setMinimumServerCertificateKeySizeRSA(minimumRSAKeySize);
        report.setMinimumServerCertificateKeySizeDSS(minimumDSSKeySize);
        report.setMinimumServerCertificateKeySizeDH(minimumDHKeySize);
    }

    @Override
    public void executeTest() {
        if (testRSA) {
            minimumRSAKeySize = getMinimumKeySize(rsaCertKeyPairs, KeyExchangeAlgorithm.RSA);
            enforcesMinimumKeySizeRSA =
                    evaluateResult(ourLargestRSAKeySize, ourSmallestRSAKeySize, minimumRSAKeySize);
        }
        if (testDSS) {
            minimumDSSKeySize =
                    getMinimumKeySize(
                            dssCertKeyPairs,
                            KeyExchangeAlgorithm.DHE_DSS,
                            KeyExchangeAlgorithm.DH_DSS);
            enforcesMinimumKeySizeDSS =
                    evaluateResult(ourLargestDSSKeySize, ourLargestDSSKeySize, minimumDSSKeySize);
        }
        if (testDH) {
            minimumDHKeySize =
                    getMinimumKeySize(
                            dhCertKeyPairs,
                            KeyExchangeAlgorithm.DH_DSS,
                            KeyExchangeAlgorithm.DH_RSA);
            enforcesMinimumKeySizeDH =
                    evaluateResult(ourLargestDHKeySize, ourSmallestDHKeySize, minimumDHKeySize);
        }
    }

    private TestResult evaluateResult(
            int ourLargestKeySize, int ourSmallestKeySize, int determinedMinimumKeySize) {
        if (determinedMinimumKeySize > ourLargestKeySize) {
            LOGGER.warn("Was unable to find any suitable minimum certificate public key size.");
            return TestResults.ERROR_DURING_TEST;
        } else if (determinedMinimumKeySize > ourSmallestKeySize) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private int getMinimumKeySize(
            List<CertificateKeyPair> certKeyPairList, KeyExchangeAlgorithm... algorithms) {
        List<KeyExchangeAlgorithm> matchingKeyExchangeAlgorithms = Arrays.asList(algorithms);
        List<CipherSuite> applicableCipherSuites =
                clientAdvertisedCipherSuites.stream()
                        .filter(
                                cipherSuite ->
                                        matchingKeyExchangeAlgorithms.contains(
                                                AlgorithmResolver.getKeyExchangeAlgorithm(
                                                        cipherSuite)))
                        .collect(Collectors.toList());
        int minimumKeySize = Integer.MAX_VALUE;

        for (CertificateKeyPair listedCertKeyPair : certKeyPairList) {
            Config config = scannerConfig.createConfig();
            config.setDefaultServerSupportedCipherSuites(applicableCipherSuites);
            config.setAutoSelectCertificate(false);
            config.setDefaultExplicitCertificateKeyPair(listedCertKeyPair);
            config.setDefaultSelectedCipherSuite(applicableCipherSuites.get(0));

            WorkflowTrace trace =
                    new WorkflowConfigurationFactory(config)
                            .createWorkflowTrace(
                                    WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER);
            trace.addTlsAction(new ReceiveAction(new AlertMessage()));
            State state = new State(config, trace);
            executeState(state);
            if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CLIENT_KEY_EXCHANGE, trace)
                    && listedCertKeyPair.getPublicKey().keySize() < minimumKeySize) {
                minimumKeySize = listedCertKeyPair.getPublicKey().keySize();
            }
        }
        return minimumKeySize;
    }

    @Override
    public void adjustConfig(ClientReport report) {
        adjustApplicableCertificates();
        testDSS = report.getResult(TlsAnalyzedProperty.SUPPORTS_DSS) == TestResults.TRUE;
        testRSA = report.getResult(TlsAnalyzedProperty.SUPPORTS_RSA) == TestResults.TRUE;
        testDH = report.getResult(TlsAnalyzedProperty.SUPPORTS_STATIC_DH) == TestResults.TRUE;
        clientAdvertisedCipherSuites = new LinkedList<>(report.getClientAdvertisedCipherSuites());
    }

    @Override
    public Requirement getRequirements() {
        return new OrRequirement(
                new PropertyRequirement(TlsAnalyzedProperty.SUPPORTS_RSA),
                new PropertyRequirement(TlsAnalyzedProperty.SUPPORTS_DSS),
                new PropertyRequirement(TlsAnalyzedProperty.SUPPORTS_STATIC_DH));
    }

    private void adjustApplicableCertificates() {
        CertificateByteChooser.getInstance()
                .getCertificateKeyPairList()
                .forEach(
                        certKeyPair -> {
                            switch (certKeyPair.getCertPublicKeyType()) {
                                case RSA:
                                    rsaCertKeyPairs.add(certKeyPair);
                                    if (certKeyPair.getPublicKey().keySize()
                                            > ourLargestRSAKeySize) {
                                        ourLargestRSAKeySize = certKeyPair.getPublicKey().keySize();
                                    } else if (certKeyPair.getPublicKey().keySize()
                                            < ourSmallestRSAKeySize) {
                                        ourSmallestRSAKeySize =
                                                certKeyPair.getPublicKey().keySize();
                                    }
                                    break;
                                case DH:
                                    dhCertKeyPairs.add(certKeyPair);
                                    if (certKeyPair.getPublicKey().keySize()
                                            > ourLargestDHKeySize) {
                                        ourLargestDHKeySize = certKeyPair.getPublicKey().keySize();
                                    } else if (certKeyPair.getPublicKey().keySize()
                                            < ourSmallestDHKeySize) {
                                        ourSmallestDHKeySize = certKeyPair.getPublicKey().keySize();
                                    }
                                    break;
                                case DSS:
                                    dssCertKeyPairs.add(certKeyPair);
                                    if (certKeyPair.getPublicKey().keySize()
                                            > ourLargestDSSKeySize) {
                                        ourLargestDSSKeySize = certKeyPair.getPublicKey().keySize();
                                    } else if (certKeyPair.getPublicKey().keySize()
                                            < ourSmallestDSSKeySize) {
                                        ourSmallestDSSKeySize =
                                                certKeyPair.getPublicKey().keySize();
                                    }
                                    break;
                                default:
                            }
                        });
    }
}
