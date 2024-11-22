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
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class CertificateProbe extends TlsServerProbe {

    private boolean scanForRsaCert = true;
    private boolean scanForDssCert = true;
    private boolean scanForEcdsaCert = true;
    private boolean scanForGostCert = true;
    private boolean scanForTls13 = true;

    // curves used for ecdsa in key exchange
    private List<X509NamedCurve> ecdsaPkGroupsStatic;
    private List<X509NamedCurve> ecdsaPkGroupsEphemeral;
    private List<X509NamedCurve> ecdsaPkGroupsTls13;

    // curves used for ecdsa certificate signatures
    private List<X509NamedCurve> ecdsaCertSigGroupsStatic;
    private List<X509NamedCurve> ecdsaCertSigGroupsEphemeral;
    private List<X509NamedCurve> ecdsaCertSigGroupsTls13;

    private Set<X509CertificateChain> certificateChains;

    public CertificateProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.CERTIFICATE, configSelector);
        register(
                TlsAnalyzedProperty.EPHEMERAL_ECDSA_PK_GROUPS,
                TlsAnalyzedProperty.STATIC_ECDSA_PK_GROUPS,
                TlsAnalyzedProperty.CERTIFICATE_CHAINS,
                TlsAnalyzedProperty.TLS13_ECDSA_PK_GROUPS,
                TlsAnalyzedProperty.STATIC_ECDSA_SIG_GROUPS,
                TlsAnalyzedProperty.EPHEMERAL_ECDSA_SIG_GROUPS,
                TlsAnalyzedProperty.TLS13_ECDSA_SIG_GROUPS);
    }

    @Override
    protected void executeTest() {
        ecdsaPkGroupsStatic = new LinkedList<>();
        ecdsaPkGroupsEphemeral = new LinkedList<>();
        ecdsaPkGroupsTls13 = new LinkedList<>();
        ecdsaCertSigGroupsStatic = new LinkedList<>();
        ecdsaCertSigGroupsEphemeral = new LinkedList<>();
        ecdsaCertSigGroupsTls13 = new LinkedList<>();

        certificateChains = new HashSet<>();
        if (configSelector.foundWorkingConfig()) {
            if (scanForRsaCert) {
                certificateChains.addAll(getRsaCerts());
            }
            if (scanForDssCert) {
                certificateChains.addAll(getDssCerts());
            }
            if (scanForEcdsaCert) {
                certificateChains.addAll(getEcdsaCerts());
            }
            if (scanForGostCert) {
                certificateChains.addAll(getGostCert());
            }
        }
        if (scanForTls13) {
            certificateChains.addAll(getTls13Certs());
        }
        if (certificateChains.isEmpty()) {
            certificateChains = null;
            ecdsaPkGroupsStatic =
                    ecdsaPkGroupsEphemeral = ecdsaPkGroupsTls13 = ecdsaCertSigGroupsTls13 = null;
        }
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProbeRequirement<>(TlsProbeType.CIPHER_SUITE, TlsProbeType.PROTOCOL_VERSION);
    }

    @Override
    public void adjustConfig(ServerReport report) {
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_RSA_CERT) == TestResults.FALSE) {
            scanForRsaCert = false;
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_ECDSA) == TestResults.FALSE) {
            scanForEcdsaCert = false;
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_DSS) == TestResults.FALSE) {
            scanForDssCert = false;
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_GOST) == TestResults.FALSE) {
            scanForGostCert = false;
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3) != TestResults.TRUE) {
            scanForTls13 = false;
        }
    }

    private List<X509CertificateChain> getRsaCerts() {
        LinkedList<X509CertificateChain> rsaCerts = new LinkedList<>();

        X509CertificateChain tlsRsaCert = getRsaCert();
        if (tlsRsaCert != null) {
            rsaCerts.add(tlsRsaCert);
        }

        X509CertificateChain dhRsaCert = getDhRsaCert();
        if (dhRsaCert != null) {
            rsaCerts.add(dhRsaCert);
        }

        X509CertificateChain ecDheRsaCert = getEcDheRsaCert();
        if (ecDheRsaCert != null) {
            rsaCerts.add(ecDheRsaCert);
        }

        rsaCerts.addAll(getEcdhRsaCerts());

        return rsaCerts;
    }

    private X509CertificateChain getRsaCert() {
        LinkedList<CipherSuite> cipherSuitesToTest = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isRealCipherSuite()
                    && AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite)
                            == KeyExchangeAlgorithm.RSA) {
                cipherSuitesToTest.add(cipherSuite);
            }
        }
        return performCertScan(configSelector.getBaseConfig(), cipherSuitesToTest);
    }

    private X509CertificateChain getDhRsaCert() {
        LinkedList<CipherSuite> cipherSuitesToTest = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isRealCipherSuite()
                    && AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite)
                            == KeyExchangeAlgorithm.DH_RSA) {
                cipherSuitesToTest.add(cipherSuite);
            }
        }
        return performCertScan(configSelector.getBaseConfig(), cipherSuitesToTest);
    }

    private X509CertificateChain getEcDheRsaCert() {
        LinkedList<CipherSuite> cipherSuitesToTest = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isRealCipherSuite()
                    && (AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite)
                                    == KeyExchangeAlgorithm.DHE_RSA
                            || AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite)
                                    == KeyExchangeAlgorithm.ECDHE_RSA)) {
                cipherSuitesToTest.add(cipherSuite);
            }
        }
        return performCertScan(configSelector.getBaseConfig(), cipherSuitesToTest);
    }

    private List<X509CertificateChain> getEcdhRsaCerts() {
        List<X509CertificateChain> ecdhRsaCerts = new LinkedList<>();
        LinkedList<CipherSuite> cipherSuitesToTest = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isRealCipherSuite()
                    && AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite)
                            == KeyExchangeAlgorithm.ECDH_RSA) {
                cipherSuitesToTest.add(cipherSuite);
            }
        }
        performEcCertScan(
                configSelector.getBaseConfig(), getAllCurves(), cipherSuitesToTest, ecdhRsaCerts);
        return ecdhRsaCerts;
    }

    private List<X509CertificateChain> getEcdsaCerts() {
        LinkedList<X509CertificateChain> ecdsaCerts = new LinkedList<>();
        ecdsaCerts.addAll(getEcdhEcdsaCerts());
        ecdsaCerts.addAll(getEcdheEcdsaCerts());
        return ecdsaCerts;
    }

    private List<X509CertificateChain> getEcdhEcdsaCerts() {
        LinkedList<X509CertificateChain> ecdhEcdsaCerts = new LinkedList<>();
        LinkedList<CipherSuite> cipherSuitesToTest = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isRealCipherSuite()
                    && AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite)
                            == KeyExchangeAlgorithm.ECDH_ECDSA) {
                cipherSuitesToTest.add(cipherSuite);
            }
        }
        performEcCertScanEcdsa(
                configSelector.getBaseConfig(),
                getAllCurves(),
                cipherSuitesToTest,
                ecdhEcdsaCerts,
                ecdsaPkGroupsStatic,
                ecdsaCertSigGroupsStatic);
        return ecdhEcdsaCerts;
    }

    private List<X509CertificateChain> getEcdheEcdsaCerts() {
        LinkedList<X509CertificateChain> ecdheEcdsaCerts = new LinkedList<>();
        LinkedList<CipherSuite> cipherSuitesToTest = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isRealCipherSuite()
                    && AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite)
                            == KeyExchangeAlgorithm.ECDHE_ECDSA) {
                cipherSuitesToTest.add(cipherSuite);
            }
        }
        performEcCertScanEcdsa(
                configSelector.getBaseConfig(),
                getAllCurves(),
                cipherSuitesToTest,
                ecdheEcdsaCerts,
                ecdsaPkGroupsEphemeral,
                ecdsaCertSigGroupsEphemeral);
        return ecdheEcdsaCerts;
    }

    private List<X509CertificateChain> getDssCerts() {
        LinkedList<X509CertificateChain> dssCerts = new LinkedList<>();

        X509CertificateChain dhDssCert = getDhDssCert();
        if (dhDssCert != null) {
            dssCerts.add(dhDssCert);
        }

        X509CertificateChain dheDssCert = getDheDssCert();
        if (dheDssCert != null) {
            dssCerts.add(dheDssCert);
        }
        return dssCerts;
    }

    private X509CertificateChain getDhDssCert() {
        LinkedList<CipherSuite> cipherSuitesToTest = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isDSS() && cipherSuite.isEphemeral() == false) {
                cipherSuitesToTest.add(cipherSuite);
            }
        }
        return performCertScan(configSelector.getBaseConfig(), cipherSuitesToTest);
    }

    private X509CertificateChain getDheDssCert() {
        LinkedList<CipherSuite> cipherSuitesToTest = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isDSS() && cipherSuite.isEphemeral()) {
                cipherSuitesToTest.add(cipherSuite);
            }
        }
        return performCertScan(configSelector.getBaseConfig(), cipherSuitesToTest);
    }

    private List<X509CertificateChain> getGostCert() {
        LinkedList<X509CertificateChain> gostCerts = new LinkedList<>();
        LinkedList<CipherSuite> cipherSuitesToTest = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isGOST()) {
                cipherSuitesToTest.add(cipherSuite);
            }
        }
        X509CertificateChain newCert =
                performCertScan(configSelector.getBaseConfig(), cipherSuitesToTest);
        if (newCert != null) {
            gostCerts.add(newCert);
        }

        return gostCerts;
    }

    private List<X509CertificateChain> getTls13Certs() {
        LinkedList<X509CertificateChain> tls13Certs = new LinkedList<>();
        X509CertificateChain rsaSigHashCert = getTls13CertRsaSigHash();
        if (rsaSigHashCert != null) {
            tls13Certs.add(rsaSigHashCert);
        }
        List<X509CertificateChain> sm2SigHashCerts = getTls13CertsSm2SigHash();
        if (sm2SigHashCerts != null) {
            tls13Certs.addAll(sm2SigHashCerts);
        }
        tls13Certs.addAll(getTls13CertsEcdsaSigHash());
        return tls13Certs;
    }

    private X509CertificateChain getTls13CertRsaSigHash() {
        Config tlsConfig = configSelector.getTls13BaseConfig();
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(getTls13RsaSigHash());
        tlsConfig.setDefaultClientNamedGroups(getTls13Curves());
        tlsConfig.setDefaultClientKeyShareNamedGroups(getTls13Curves());
        return performCertScan(tlsConfig, CipherSuite.getImplementedTls13CipherSuites());
    }

    private List<X509CertificateChain> getTls13CertsEcdsaSigHash() {
        Config tlsConfig = configSelector.getTls13BaseConfig();
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(getTls13EcdsaSigHash());
        List<X509CertificateChain> tls13ecdsaCerts = new LinkedList<>();
        performEcCertScanEcdsa(
                tlsConfig,
                getTls13Curves(),
                CipherSuite.getImplementedTls13CipherSuites(),
                tls13ecdsaCerts,
                ecdsaPkGroupsTls13,
                ecdsaCertSigGroupsTls13);
        return tls13ecdsaCerts;
    }

    private List<X509CertificateChain> getTls13CertsSm2SigHash() {
        Config tlsConfig = configSelector.getTls13BaseConfig();
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(
                SignatureAndHashAlgorithm.SM2_SM3);
        List<X509CertificateChain> tls13Sm2Certs = new LinkedList<>();
        performEcCertScanEcdsa(
                tlsConfig,
                getTls13Curves(),
                CipherSuite.getImplementedTls13CipherSuites(),
                tls13Sm2Certs,
                ecdsaPkGroupsTls13,
                ecdsaCertSigGroupsTls13);
        return tls13Sm2Certs;
    }

    private List<NamedGroup> getAllCurves() {
        LinkedList<NamedGroup> curves = new LinkedList<>();

        for (NamedGroup group : NamedGroup.values()) {
            if (group.isEcGroup()) {
                curves.add(group);
            }
        }
        return curves;
    }

    private List<NamedGroup> getTls13Curves() {
        LinkedList<NamedGroup> curves = new LinkedList<>();
        for (NamedGroup group : NamedGroup.values()) {
            if (group.isCurve() && group.isTls13()) {
                curves.add(group);
            }
        }
        return curves;
    }

    private X509CertificateChain performCertScan(
            Config tlsConfig, List<CipherSuite> cipherSuitesToTest) {
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuitesToTest);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        configSelector.repairConfig(tlsConfig);
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceResultUtil.didReceiveMessage(
                        state.getWorkflowTrace(), HandshakeMessageType.CERTIFICATE)
                && cipherSuitesToTest.contains(state.getTlsContext().getSelectedCipherSuite())
                && state.getTlsContext().getServerCertificateChain() != null) {
            return state.getTlsContext().getServerCertificateChain();
        } else {
            return null;
        }
    }

    private void performEcCertScan(
            Config tlsConfig,
            List<NamedGroup> groupsToTest,
            List<CipherSuite> cipherSuitesToTest,
            List<X509CertificateChain> certificateList) {
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuitesToTest);
        tlsConfig.setDefaultClientNamedGroups(groupsToTest);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        configSelector.repairConfig(tlsConfig);
        do {
            State state = new State(tlsConfig);
            executeState(state);
            if (WorkflowTraceResultUtil.didReceiveMessage(
                            state.getWorkflowTrace(), HandshakeMessageType.CERTIFICATE)
                    && cipherSuitesToTest.contains(state.getTlsContext().getSelectedCipherSuite())
                    && state.getTlsContext().getServerCertificateChain() != null
                    && state.getTlsContext()
                                    .getServerCertificateChain()
                                    .getLeaf()
                                    .getEllipticCurve()
                            != null
                    && groupsToTest.contains(
                            state.getTlsContext()
                                    .getServerCertificateChain()
                                    .getLeaf()
                                    .getEllipticCurve())) {
                groupsToTest.remove(
                        state.getTlsContext()
                                .getServerCertificateChain()
                                .getLeaf()
                                .getEllipticCurve());
                certificateList.add(state.getTlsContext().getServerCertificateChain());
            } else {
                // selected cipher suite or certificate named group invalid
                cipherSuitesToTest.clear();
                groupsToTest.clear();
            }
        } while (!groupsToTest.isEmpty() && !cipherSuitesToTest.isEmpty());
    }

    private void performEcCertScanEcdsa(
            Config tlsConfig,
            List<NamedGroup> groupsToTest,
            List<CipherSuite> cipherSuitesToTest,
            List<X509CertificateChain> certificateList,
            List<X509NamedCurve> pkGroups,
            List<X509NamedCurve> sigGroups) {
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuitesToTest);
        tlsConfig.setDefaultClientNamedGroups(groupsToTest);
        tlsConfig.setDefaultClientKeyShareNamedGroups(groupsToTest);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        configSelector.repairConfig(tlsConfig);
        do {
            State state = new State(tlsConfig);
            executeState(state);
            if (WorkflowTraceResultUtil.didReceiveMessage(
                            state.getWorkflowTrace(), HandshakeMessageType.CERTIFICATE)
                    && cipherSuitesToTest.contains(state.getTlsContext().getSelectedCipherSuite())
                    && state.getTlsContext().getServerCertificateChain() != null
                    && state.getTlsContext()
                                    .getServerCertificateChain()
                                    .getLeaf()
                                    .getEllipticCurve()
                            != null
                    && groupsToTest.contains(
                            state.getTlsContext()
                                    .getServerCertificateChain()
                                    .getLeaf()
                                    .getEllipticCurve())) {
                groupsToTest.remove(
                        state.getTlsContext().getServerX509Context().getSubjectNamedCurve());
                certificateList.add(state.getTlsContext().getServerCertificateChain());
                pkGroups.add(state.getTlsContext().getServerX509Context().getSubjectNamedCurve());
                if (state.getTlsContext().getServerX509Context().getIssuerNamedCurve() != null
                        && !sigGroups.contains(
                                state.getTlsContext()
                                        .getServerX509Context()
                                        .getIssuerNamedCurve())) {
                    sigGroups.add(
                            state.getTlsContext().getServerX509Context().getIssuerNamedCurve());
                }
            } else {
                // selected cipher suite or certificate named group invalid
                cipherSuitesToTest.clear();
                groupsToTest.clear();
            }
        } while (!groupsToTest.isEmpty() && !cipherSuitesToTest.isEmpty());
    }

    private List<SignatureAndHashAlgorithm> getTls13RsaSigHash() {
        List<SignatureAndHashAlgorithm> algorithms = new LinkedList<>();
        for (SignatureAndHashAlgorithm algorithm :
                SignatureAndHashAlgorithm.getImplementedTls13SignatureAndHashAlgorithms()) {
            if (algorithm.name().contains("RSA")) {
                algorithms.add(algorithm);
            }
        }
        return algorithms;
    }

    private List<SignatureAndHashAlgorithm> getTls13EcdsaSigHash() {
        List<SignatureAndHashAlgorithm> algorithms = new LinkedList<>();
        for (SignatureAndHashAlgorithm algorithm :
                SignatureAndHashAlgorithm.getImplementedTls13SignatureAndHashAlgorithms()) {
            if (algorithm.name().contains("ECDSA")) {
                algorithms.add(algorithm);
            }
        }
        return algorithms;
    }

    @Override
    protected void mergeData(ServerReport report) {
        List<CertificateChainReport> certificateChainReports = new LinkedList<>();

        if (certificateChains != null) {
            for (X509CertificateChain chain : certificateChains) {
                certificateChainReports.add(
                        new CertificateChainReport(
                                chain,
                                configSelector
                                        .getBaseConfig()
                                        .getDefaultClientConnection()
                                        .getHostname()));
            }
        }
        put(TlsAnalyzedProperty.CERTIFICATE_CHAINS, certificateChainReports);
        put(TlsAnalyzedProperty.STATIC_ECDSA_PK_GROUPS, ecdsaPkGroupsStatic);
        put(TlsAnalyzedProperty.EPHEMERAL_ECDSA_PK_GROUPS, ecdsaPkGroupsEphemeral);
        put(TlsAnalyzedProperty.TLS13_ECDSA_PK_GROUPS, ecdsaPkGroupsTls13);
        put(TlsAnalyzedProperty.STATIC_ECDSA_SIG_GROUPS, ecdsaCertSigGroupsStatic);
        put(TlsAnalyzedProperty.EPHEMERAL_ECDSA_SIG_GROUPS, ecdsaCertSigGroupsEphemeral);
        put(TlsAnalyzedProperty.TLS13_ECDSA_SIG_GROUPS, ecdsaCertSigGroupsTls13);
    }
}
