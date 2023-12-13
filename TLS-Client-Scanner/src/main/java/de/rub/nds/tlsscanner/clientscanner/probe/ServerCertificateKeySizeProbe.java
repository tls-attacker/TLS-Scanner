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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
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
        // TODO readd properly with x509 attacker
    }

    @Override
    public void adjustConfig(ClientReport report) {
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
}
