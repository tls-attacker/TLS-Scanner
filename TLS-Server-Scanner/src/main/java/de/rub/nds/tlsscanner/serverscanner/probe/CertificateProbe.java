/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class CertificateProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private boolean scanForRsaCert = true;
    private boolean scanForDssCert = true;
    private boolean scanForEcdsaCert = true;
    private boolean scanForGostCert = true;
    private boolean scanForTls13 = true;

    // curves used for ecdsa in key exchange
    private List<NamedGroup> ecdsaPkGroupsStatic;
    private List<NamedGroup> ecdsaPkGroupsEphemeral;
    private List<NamedGroup> ecdsaPkGroupsTls13;

    // curves used for ecdsa certificate signatures
    private List<NamedGroup> ecdsaCertSigGroupsStatic;
    private List<NamedGroup> ecdsaCertSigGroupsEphemeral;
    private List<NamedGroup> ecdsaCertSigGroupsTls13;

    private Set<CertificateChainReport> certificates;

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
    public void executeTest() {
        ecdsaPkGroupsStatic = new LinkedList<>();
        ecdsaPkGroupsEphemeral = new LinkedList<>();
        ecdsaPkGroupsTls13 = new LinkedList<>();
        ecdsaCertSigGroupsStatic = new LinkedList<>();
        ecdsaCertSigGroupsEphemeral = new LinkedList<>();
        ecdsaCertSigGroupsTls13 = new LinkedList<>();

        certificates = new HashSet<>();
        if (configSelector.foundWorkingConfig()) {
            if (scanForRsaCert) {
                certificates.addAll(getRsaCerts());
            }
            if (scanForDssCert) {
                certificates.addAll(getDssCerts());
            }
            if (scanForEcdsaCert) {
                certificates.addAll(getEcdsaCerts());
            }
            if (scanForGostCert) {
                certificates.addAll(getGostCert());
            }
        }
        if (scanForTls13) {
            certificates.addAll(getTls13Certs());
        }
        if (certificates.isEmpty()) {
            certificates = null;
            ecdsaPkGroupsStatic =
                    ecdsaPkGroupsEphemeral = ecdsaPkGroupsTls13 = ecdsaCertSigGroupsTls13 = null;
        }
    }

    @Override
    protected Requirement getRequirements() {
        return new ProbeRequirement(TlsProbeType.CIPHER_SUITE, TlsProbeType.PROTOCOL_VERSION);
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

    private List<CertificateChainReport> getRsaCerts() {
        LinkedList<CertificateChainReport> rsaCerts = new LinkedList<>();

        CertificateChainReport tlsRsaCert = getRsaCert();
        if (tlsRsaCert != null) {
            rsaCerts.add(tlsRsaCert);
        }

        CertificateChainReport dhRsaCert = getDhRsaCert();
        if (dhRsaCert != null) {
            rsaCerts.add(dhRsaCert);
        }

        CertificateChainReport ecDheRsaCert = getEcDheRsaCert();
        if (ecDheRsaCert != null) {
            rsaCerts.add(ecDheRsaCert);
        }

        rsaCerts.addAll(getEcdhRsaCerts());

        return rsaCerts;
    }

    private CertificateChainReport getRsaCert() {
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

    private CertificateChainReport getDhRsaCert() {
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

    private CertificateChainReport getEcDheRsaCert() {
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

    private List<CertificateChainReport> getEcdhRsaCerts() {
        List<CertificateChainReport> ecdhRsaCerts = new LinkedList<>();
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

    private List<CertificateChainReport> getEcdsaCerts() {
        LinkedList<CertificateChainReport> ecdsaCerts = new LinkedList<>();
        ecdsaCerts.addAll(getEcdhEcdsaCerts());
        ecdsaCerts.addAll(getEcdheEcdsaCerts());
        return ecdsaCerts;
    }

    private List<CertificateChainReport> getEcdhEcdsaCerts() {
        LinkedList<CertificateChainReport> ecdhEcdsaCerts = new LinkedList<>();
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

    private List<CertificateChainReport> getEcdheEcdsaCerts() {
        LinkedList<CertificateChainReport> ecdheEcdsaCerts = new LinkedList<>();
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

    private List<CertificateChainReport> getDssCerts() {
        LinkedList<CertificateChainReport> dssCerts = new LinkedList<>();

        CertificateChainReport dhDssCert = getDhDssCert();
        if (dhDssCert != null) {
            dssCerts.add(dhDssCert);
        }

        CertificateChainReport dheDssCert = getDheDssCert();
        if (dheDssCert != null) {
            dssCerts.add(dheDssCert);
        }
        return dssCerts;
    }

    private CertificateChainReport getDhDssCert() {
        LinkedList<CipherSuite> cipherSuitesToTest = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isDSS() && cipherSuite.isEphemeral() == false) {
                cipherSuitesToTest.add(cipherSuite);
            }
        }
        return performCertScan(configSelector.getBaseConfig(), cipherSuitesToTest);
    }

    private CertificateChainReport getDheDssCert() {
        LinkedList<CipherSuite> cipherSuitesToTest = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isDSS() && cipherSuite.isEphemeral()) {
                cipherSuitesToTest.add(cipherSuite);
            }
        }
        return performCertScan(configSelector.getBaseConfig(), cipherSuitesToTest);
    }

    private List<CertificateChainReport> getGostCert() {
        LinkedList<CertificateChainReport> gostCerts = new LinkedList<>();
        LinkedList<CipherSuite> cipherSuitesToTest = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isGOST()) {
                cipherSuitesToTest.add(cipherSuite);
            }
        }
        CertificateChainReport newCert =
                performCertScan(configSelector.getBaseConfig(), cipherSuitesToTest);
        if (newCert != null) {
            gostCerts.add(newCert);
        }

        return gostCerts;
    }

    private List<CertificateChainReport> getTls13Certs() {
        LinkedList<CertificateChainReport> tls13Certs = new LinkedList<>();
        CertificateChainReport rsaSigHashCert = getTls13CertRsaSigHash();
        if (rsaSigHashCert != null) {
            tls13Certs.add(rsaSigHashCert);
        }
        tls13Certs.addAll(getTls13CertsEcdsaSigHash());
        return tls13Certs;
    }

    private CertificateChainReport getTls13CertRsaSigHash() {
        Config tlsConfig = configSelector.getTls13BaseConfig();
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(getTls13RsaSigHash());
        tlsConfig.setDefaultClientNamedGroups(getTls13Curves());
        tlsConfig.setDefaultClientKeyShareNamedGroups(getTls13Curves());
        return performCertScan(tlsConfig, CipherSuite.getImplementedTls13CipherSuites());
    }

    private List<CertificateChainReport> getTls13CertsEcdsaSigHash() {
        Config tlsConfig = configSelector.getTls13BaseConfig();
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(getTls13EcdsaSigHash());
        List<CertificateChainReport> tls13ecdsaCerts = new LinkedList<>();
        performEcCertScanEcdsa(
                tlsConfig,
                getTls13Curves(),
                CipherSuite.getImplementedTls13CipherSuites(),
                tls13ecdsaCerts,
                ecdsaPkGroupsTls13,
                ecdsaCertSigGroupsTls13);
        return tls13ecdsaCerts;
    }

    private List<NamedGroup> getAllCurves() {
        LinkedList<NamedGroup> curves = new LinkedList<>();

        for (NamedGroup group : NamedGroup.values()) {
            if (group.isCurve()) {
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

    private CertificateChainReport performCertScan(
            Config tlsConfig, List<CipherSuite> cipherSuitesToTest) {
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuitesToTest);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        configSelector.repairConfig(tlsConfig);
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(
                        HandshakeMessageType.CERTIFICATE, state.getWorkflowTrace())
                && cipherSuitesToTest.contains(state.getTlsContext().getSelectedCipherSuite())
                && state.getTlsContext().getServerCertificateChain() != null) {
            return new CertificateChainReport(
                    state.getTlsContext().getServerCertificateChain(),
                    tlsConfig.getDefaultClientConnection().getHostname());
        } else {
            return null;
        }
    }

    private void performEcCertScan(
            Config tlsConfig,
            List<NamedGroup> groupsToTest,
            List<CipherSuite> cipherSuitesToTest,
            List<CertificateChainReport> certificateList) {
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuitesToTest);
        tlsConfig.setDefaultClientNamedGroups(groupsToTest);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        configSelector.repairConfig(tlsConfig);
        do {
            State state = new State(tlsConfig);
            executeState(state);
            if (WorkflowTraceUtil.didReceiveMessage(
                            HandshakeMessageType.CERTIFICATE, state.getWorkflowTrace())
                    && cipherSuitesToTest.contains(state.getTlsContext().getSelectedCipherSuite())
                    && state.getTlsContext().getServerCertificateChain() != null
                    && state.getTlsContext().getServerCertificateChain().getLeaf().getEllipticCurve() != null
                    && groupsToTest.contains(state.getTlsContext().getServerCertificateChain().getLeaf().getEllipticCurve() )) {
                groupsToTest.remove(state.getTlsContext().getServerCertificateChain().getLeaf().getEllipticCurve() );
                certificateList.add(
                        new CertificateChainReport(
                                state.getTlsContext().getServerCertificateChain(),
                                tlsConfig.getDefaultClientConnection().getHostname()));
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
            List<CertificateChainReport> certificateList,
            List<NamedGroup> pkGroups,
            List<NamedGroup> sigGroups) {
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuitesToTest);
        tlsConfig.setDefaultClientNamedGroups(groupsToTest);
        tlsConfig.setDefaultClientKeyShareNamedGroups(groupsToTest);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        configSelector.repairConfig(tlsConfig);
        do {
            State state = new State(tlsConfig);
            executeState(state);
            if (WorkflowTraceUtil.didReceiveMessage(
                            HandshakeMessageType.CERTIFICATE, state.getWorkflowTrace())
                    && cipherSuitesToTest.contains(state.getTlsContext().getSelectedCipherSuite())
                    && state.getTlsContext().getServerCertificateChain() != null
                    && state.getTlsContext().getEcCertificateCurve() != null
                    && groupsToTest.contains(state.getTlsContext().getEcCertificateCurve())) {
                groupsToTest.remove(state.getTlsContext().getEcCertificateCurve());
                certificateList.add(
                        new CertificateChainReport(
                                state.getTlsContext().getServerCertificate(),
                                tlsConfig.getDefaultClientConnection().getHostname()));
                pkGroups.add(state.getTlsContext().getEcCertificateCurve());
                if (state.getTlsContext().getEcCertificateSignatureCurve() != null
                        && !sigGroups.contains(
                                state.getTlsContext().getEcCertificateSignatureCurve())) {
                    sigGroups.add(state.getTlsContext().getEcCertificateSignatureCurve());
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
        if (certificates != null) {
            put(TlsAnalyzedProperty.CERTIFICATE_CHAINS, new ArrayList<>(certificates));
        } else {
            put(TlsAnalyzedProperty.CERTIFICATE_CHAINS, new LinkedList<>());
        }
        put(TlsAnalyzedProperty.STATIC_ECDSA_PK_GROUPS, ecdsaPkGroupsStatic);
        put(TlsAnalyzedProperty.EPHEMERAL_ECDSA_PK_GROUPS, ecdsaPkGroupsEphemeral);
        put(TlsAnalyzedProperty.TLS13_ECDSA_PK_GROUPS, ecdsaPkGroupsTls13);
        put(TlsAnalyzedProperty.STATIC_ECDSA_SIG_GROUPS, ecdsaCertSigGroupsStatic);
        put(TlsAnalyzedProperty.EPHEMERAL_ECDSA_SIG_GROUPS, ecdsaCertSigGroupsEphemeral);
        put(TlsAnalyzedProperty.TLS13_ECDSA_SIG_GROUPS, ecdsaCertSigGroupsTls13);
    }
}
