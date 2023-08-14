/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.PropertyTrueRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.certificate.CertificateByteChooser;
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.config.Config;
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
import java.util.LinkedList;
import java.util.List;

public class ServerCertificateKeySizeProbe extends TlsClientProbe {

    public static final String NO_MINIMUM_KEY_SIZE_FOUND = "No minimum key size could be detected";

    private TestResult enforcesMinimumKeySizeRSA = TestResults.COULD_NOT_TEST;
    private TestResult enforcesMinimumKeySizeRSASig = TestResults.COULD_NOT_TEST;
    private TestResult enforcesMinimumKeySizeDSS = TestResults.COULD_NOT_TEST;
    private TestResult enforcesMinimumKeySizeDH = TestResults.COULD_NOT_TEST;

    private List<CertificateKeyPair> rsaCertKeyPairs = new LinkedList<>();
    private List<CertificateKeyPair> dssCertKeyPairs = new LinkedList<>();
    private List<CertificateKeyPair> dhCertKeyPairs = new LinkedList<>();

    private List<CipherSuite> rsaKexCipherSuites,
            rsaSigCipherSuites,
            dssCipherSuites,
            dhCipherSuites;
    private int minimumRSAKeySize, minimumRSASigKeySize, minimumDSSKeySize, minimumDHKeySize;

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
                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_RSA_SIG,
                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_DH,
                TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_RSA,
                TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_RSA_SIG,
                TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_DSS,
                TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_DH);
    }

    @Override
    protected void mergeData(ClientReport report) {
        put(
                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_RSA_SIG,
                enforcesMinimumKeySizeRSASig);
        put(TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_RSA, enforcesMinimumKeySizeRSA);
        put(TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_DSS, enforcesMinimumKeySizeDSS);
        put(TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_DH, enforcesMinimumKeySizeDH);

        putIfTrue(
                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_RSA_SIG,
                TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_RSA_SIG,
                minimumRSASigKeySize,
                NO_MINIMUM_KEY_SIZE_FOUND);
        putIfTrue(
                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_RSA,
                TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_RSA,
                minimumRSAKeySize,
                NO_MINIMUM_KEY_SIZE_FOUND);
        putIfTrue(
                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_DSS,
                TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_DSS,
                minimumDSSKeySize,
                NO_MINIMUM_KEY_SIZE_FOUND);
        putIfTrue(
                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_DH,
                TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_DH,
                minimumDHKeySize,
                NO_MINIMUM_KEY_SIZE_FOUND);
    }

    @Override
    protected void executeTest() {
        if (!rsaKexCipherSuites.isEmpty()) {
            minimumRSAKeySize = getMinimumKeySize(rsaCertKeyPairs, rsaKexCipherSuites);
            enforcesMinimumKeySizeRSA =
                    evaluateResult(ourLargestRSAKeySize, ourSmallestRSAKeySize, minimumRSAKeySize);
        }
        if (!rsaSigCipherSuites.isEmpty()) {
            minimumRSASigKeySize = getMinimumKeySize(rsaCertKeyPairs, rsaSigCipherSuites);
            enforcesMinimumKeySizeRSASig =
                    evaluateResult(
                            ourLargestRSAKeySize, ourSmallestRSAKeySize, minimumRSASigKeySize);
        }
        if (!dssCipherSuites.isEmpty()) {
            minimumDSSKeySize = getMinimumKeySize(dssCertKeyPairs, dssCipherSuites);
            enforcesMinimumKeySizeDSS =
                    evaluateResult(ourLargestDSSKeySize, ourLargestDSSKeySize, minimumDSSKeySize);
        }
        if (!dhCipherSuites.isEmpty()) {
            minimumDHKeySize = getMinimumKeySize(dhCertKeyPairs, dhCipherSuites);
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
            List<CertificateKeyPair> certKeyPairList, List<CipherSuite> cipherSuitesToTest) {
        int minimumKeySize = Integer.MAX_VALUE;

        for (CertificateKeyPair listedCertKeyPair : certKeyPairList) {
            Config config = scannerConfig.createConfig();
            config.setDefaultServerSupportedCipherSuites(cipherSuitesToTest);
            config.setAutoSelectCertificate(false);
            config.setDefaultExplicitCertificateKeyPair(listedCertKeyPair);
            config.setDefaultSelectedCipherSuite(cipherSuitesToTest.get(0));

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
        dssCipherSuites =
                report.getSupportedCipherSuitesWithKeyExchange(
                        KeyExchangeAlgorithm.DHE_DSS, KeyExchangeAlgorithm.DH_DSS);
        rsaKexCipherSuites =
                report.getSupportedCipherSuitesWithKeyExchange(KeyExchangeAlgorithm.RSA);
        rsaSigCipherSuites =
                report.getSupportedCipherSuitesWithKeyExchange(
                        KeyExchangeAlgorithm.DHE_RSA, KeyExchangeAlgorithm.ECDHE_RSA);
        dhCipherSuites =
                report.getSupportedCipherSuitesWithKeyExchange(
                        KeyExchangeAlgorithm.DH_DSS, KeyExchangeAlgorithm.DH_RSA);
        clientAdvertisedCipherSuites = new LinkedList<>(report.getClientAdvertisedCipherSuites());
    }

    @Override
    public Requirement<ClientReport> getRequirements() {
        return new PropertyTrueRequirement<ClientReport>(TlsAnalyzedProperty.SUPPORTS_RSA)
                .or(new PropertyTrueRequirement<>(TlsAnalyzedProperty.SUPPORTS_DSS))
                .or(new PropertyTrueRequirement<>(TlsAnalyzedProperty.SUPPORTS_STATIC_DH));
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
