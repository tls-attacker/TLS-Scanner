/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

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
import de.rub.nds.tlsscanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

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

    private Set<CertificateChain> certificates;

    public CertificateProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.CERTIFICATE, configSelector);
        register(TlsAnalyzedProperty.LIST_EPHEMERAL_ECDSA_PKGROUPS, TlsAnalyzedProperty.LIST_STATIC_ECDSA_PKGROUPS,
            TlsAnalyzedProperty.LIST_CERTIFICATE_CHAINS);
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
        if (scanForTls13) {
            certificates.addAll(getTls13Certs());
        }
        if (certificates.isEmpty()) {
            certificates = null;
            ecdsaPkGroupsStatic = ecdsaPkGroupsEphemeral = ecdsaPkGroupsTls13 = ecdsaCertSigGroupsTls13 = null;
        }
    }

    @Override
    protected Requirement requires() {
        return new ProbeRequirement().requireProbeTypes(TlsProbeType.CIPHER_SUITE, TlsProbeType.PROTOCOL_VERSION);
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

    private List<CertificateChain> getRsaCerts() {
        LinkedList<CertificateChain> rsaCerts = new LinkedList<>();

        CertificateChain tlsRsaCert = getRsaCert();
        if (tlsRsaCert != null) {
            rsaCerts.add(tlsRsaCert);
        }

        CertificateChain dhRsaCert = getDhRsaCert();
        if (dhRsaCert != null) {
            rsaCerts.add(dhRsaCert);
        }

        CertificateChain ecDheRsaCert = getEcDheRsaCert();
        if (ecDheRsaCert != null) {
            rsaCerts.add(ecDheRsaCert);
        }

        rsaCerts.addAll(getEcdhRsaCerts());

        return rsaCerts;
    }

    private CertificateChain getRsaCert() {
        LinkedList<CipherSuite> cipherSuitesToTest = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isRealCipherSuite()
                && AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite) == KeyExchangeAlgorithm.RSA) {
                cipherSuitesToTest.add(cipherSuite);
            }
        }
        return performCertScan(configSelector.getBaseConfig(), cipherSuitesToTest);
    }

    private CertificateChain getDhRsaCert() {
        LinkedList<CipherSuite> cipherSuitesToTest = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isRealCipherSuite()
                && AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite) == KeyExchangeAlgorithm.DH_RSA) {
                cipherSuitesToTest.add(cipherSuite);
            }
        }
        return performCertScan(configSelector.getBaseConfig(), cipherSuitesToTest);
    }

    private CertificateChain getEcDheRsaCert() {
        LinkedList<CipherSuite> cipherSuitesToTest = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isRealCipherSuite()
                && (AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite) == KeyExchangeAlgorithm.DHE_RSA
                    || AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite) == KeyExchangeAlgorithm.ECDHE_RSA)) {
                cipherSuitesToTest.add(cipherSuite);
            }
        }
        return performCertScan(configSelector.getBaseConfig(), cipherSuitesToTest);
    }

    private List<CertificateChain> getEcdhRsaCerts() {
        List<CertificateChain> ecdhRsaCerts = new LinkedList<>();
        LinkedList<CipherSuite> cipherSuitesToTest = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isRealCipherSuite()
                && AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite) == KeyExchangeAlgorithm.ECDH_RSA) {
                cipherSuitesToTest.add(cipherSuite);
            }
        }
        performEcCertScan(configSelector.getBaseConfig(), getAllCurves(), cipherSuitesToTest, ecdhRsaCerts);
        return ecdhRsaCerts;
    }

    private List<CertificateChain> getEcdsaCerts() {
        LinkedList<CertificateChain> ecdsaCerts = new LinkedList<>();
        ecdsaCerts.addAll(getEcdhEcdsaCerts());
        ecdsaCerts.addAll(getEcdheEcdsaCerts());
        return ecdsaCerts;
    }

    private List<CertificateChain> getEcdhEcdsaCerts() {
        LinkedList<CertificateChain> ecdhEcdsaCerts = new LinkedList<>();
        LinkedList<CipherSuite> cipherSuitesToTest = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isRealCipherSuite()
                && AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite) == KeyExchangeAlgorithm.ECDH_ECDSA) {
                cipherSuitesToTest.add(cipherSuite);
            }
        }
        performEcCertScanEcdsa(configSelector.getBaseConfig(), getAllCurves(), cipherSuitesToTest, ecdhEcdsaCerts,
            ecdsaPkGroupsStatic, ecdsaCertSigGroupsStatic);
        return ecdhEcdsaCerts;
    }

    private List<CertificateChain> getEcdheEcdsaCerts() {
        LinkedList<CertificateChain> ecdheEcdsaCerts = new LinkedList<>();
        LinkedList<CipherSuite> cipherSuitesToTest = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isRealCipherSuite()
                && AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite) == KeyExchangeAlgorithm.ECDHE_ECDSA) {
                cipherSuitesToTest.add(cipherSuite);
            }
        }
        performEcCertScanEcdsa(configSelector.getBaseConfig(), getAllCurves(), cipherSuitesToTest, ecdheEcdsaCerts,
            ecdsaPkGroupsEphemeral, ecdsaCertSigGroupsEphemeral);
        return ecdheEcdsaCerts;
    }

    private List<CertificateChain> getDssCerts() {
        LinkedList<CertificateChain> dssCerts = new LinkedList<>();

        CertificateChain dhDssCert = getDhDssCert();
        if (dhDssCert != null) {
            dssCerts.add(dhDssCert);
        }

        CertificateChain dheDssCert = getDheDssCert();
        if (dheDssCert != null) {
            dssCerts.add(dheDssCert);
        }
        return dssCerts;
    }

    private CertificateChain getDhDssCert() {
        LinkedList<CipherSuite> cipherSuitesToTest = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isDSS() && cipherSuite.isEphemeral() == false) {
                cipherSuitesToTest.add(cipherSuite);
            }
        }
        return performCertScan(configSelector.getBaseConfig(), cipherSuitesToTest);
    }

    private CertificateChain getDheDssCert() {
        LinkedList<CipherSuite> cipherSuitesToTest = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isDSS() && cipherSuite.isEphemeral()) {
                cipherSuitesToTest.add(cipherSuite);
            }
        }
        return performCertScan(configSelector.getBaseConfig(), cipherSuitesToTest);
    }

    private List<CertificateChain> getGostCert() {
        LinkedList<CertificateChain> gostCerts = new LinkedList<>();
        LinkedList<CipherSuite> cipherSuitesToTest = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isGOST()) {
                cipherSuitesToTest.add(cipherSuite);
            }
        }
        CertificateChain newCert = performCertScan(configSelector.getBaseConfig(), cipherSuitesToTest);
        if (newCert != null) {
            gostCerts.add(newCert);
        }

        return gostCerts;
    }

    private List<CertificateChain> getTls13Certs() {
        LinkedList<CertificateChain> tls13Certs = new LinkedList<>();
        CertificateChain rsaSigHashCert = getTls13CertRsaSigHash();
        if (rsaSigHashCert != null) {
            tls13Certs.add(rsaSigHashCert);
        }
        tls13Certs.addAll(getTls13CertsEcdsaSigHash());
        return tls13Certs;
    }

    private CertificateChain getTls13CertRsaSigHash() {
        Config tlsConfig = configSelector.getTls13BaseConfig();
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(getTls13RsaSigHash());
        tlsConfig.setDefaultClientNamedGroups(getTls13Curves());
        tlsConfig.setDefaultClientKeyShareNamedGroups(getTls13Curves());
        return performCertScan(tlsConfig, CipherSuite.getImplementedTls13CipherSuites());
    }

    private List<CertificateChain> getTls13CertsEcdsaSigHash() {
        Config tlsConfig = configSelector.getTls13BaseConfig();
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(getTls13EcdsaSigHash());
        List<CertificateChain> tls13ecdsaCerts = new LinkedList<>();
        performEcCertScanEcdsa(tlsConfig, getTls13Curves(), CipherSuite.getImplementedTls13CipherSuites(),
            tls13ecdsaCerts, ecdsaPkGroupsTls13, ecdsaCertSigGroupsTls13);
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

    private CertificateChain performCertScan(Config tlsConfig, List<CipherSuite> cipherSuitesToTest) {
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuitesToTest);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        configSelector.repairConfig(tlsConfig);
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CERTIFICATE, state.getWorkflowTrace())
            && cipherSuitesToTest.contains(state.getTlsContext().getSelectedCipherSuite())
            && state.getTlsContext().getServerCertificate() != null) {
            return new CertificateChain(state.getTlsContext().getServerCertificate(),
                tlsConfig.getDefaultClientConnection().getHostname());
        } else {
            return null;
        }
    }

    private void performEcCertScan(Config tlsConfig, List<NamedGroup> groupsToTest,
        List<CipherSuite> cipherSuitesToTest, List<CertificateChain> certificateList) {
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuitesToTest);
        tlsConfig.setDefaultClientNamedGroups(groupsToTest);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        configSelector.repairConfig(tlsConfig);
        do {
            State state = new State(tlsConfig);
            executeState(state);
            if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CERTIFICATE, state.getWorkflowTrace())
                && cipherSuitesToTest.contains(state.getTlsContext().getSelectedCipherSuite())
                && state.getTlsContext().getServerCertificate() != null
                && state.getTlsContext().getEcCertificateCurve() != null
                && groupsToTest.contains(state.getTlsContext().getEcCertificateCurve())) {
                groupsToTest.remove(state.getTlsContext().getEcCertificateCurve());
                certificateList.add(new CertificateChain(state.getTlsContext().getServerCertificate(),
                    tlsConfig.getDefaultClientConnection().getHostname()));
            } else {
                // selected cipher suite or certificate named group invalid
                cipherSuitesToTest.clear();
                groupsToTest.clear();
            }
        } while (!groupsToTest.isEmpty() && !cipherSuitesToTest.isEmpty());
    }

    private void performEcCertScanEcdsa(Config tlsConfig, List<NamedGroup> groupsToTest,
        List<CipherSuite> cipherSuitesToTest, List<CertificateChain> certificateList, List<NamedGroup> pkGroups,
        List<NamedGroup> sigGroups) {
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuitesToTest);
        tlsConfig.setDefaultClientNamedGroups(groupsToTest);
        tlsConfig.setDefaultClientKeyShareNamedGroups(groupsToTest);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        configSelector.repairConfig(tlsConfig);
        do {
            State state = new State(tlsConfig);
            executeState(state);
            if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CERTIFICATE, state.getWorkflowTrace())
                && cipherSuitesToTest.contains(state.getTlsContext().getSelectedCipherSuite())
                && state.getTlsContext().getServerCertificate() != null
                && state.getTlsContext().getEcCertificateCurve() != null
                && groupsToTest.contains(state.getTlsContext().getEcCertificateCurve())) {
                groupsToTest.remove(state.getTlsContext().getEcCertificateCurve());
                certificateList.add(new CertificateChain(state.getTlsContext().getServerCertificate(),
                    tlsConfig.getDefaultClientConnection().getHostname()));
                pkGroups.add(state.getTlsContext().getEcCertificateCurve());
                if (state.getTlsContext().getEcCertificateSignatureCurve() != null
                    && !sigGroups.contains(state.getTlsContext().getEcCertificateSignatureCurve())) {
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
        for (SignatureAndHashAlgorithm algorithm : SignatureAndHashAlgorithm
            .getImplementedTls13SignatureAndHashAlgorithms()) {
            if (algorithm.name().contains("RSA")) {
                algorithms.add(algorithm);
            }
        }
        return algorithms;
    }

    private List<SignatureAndHashAlgorithm> getTls13EcdsaSigHash() {
        List<SignatureAndHashAlgorithm> algorithms = new LinkedList<>();
        for (SignatureAndHashAlgorithm algorithm : SignatureAndHashAlgorithm
            .getImplementedTls13SignatureAndHashAlgorithms()) {
            if (algorithm.name().contains("ECDSA")) {
                algorithms.add(algorithm);
            }
        }
        return algorithms;
    }

    @Override
    protected void mergeData(ServerReport report) {
        if (certificates != null)
            put(TlsAnalyzedProperty.LIST_CERTIFICATE_CHAINS, new ArrayList<>(certificates));
        else
            put(TlsAnalyzedProperty.LIST_CERTIFICATE_CHAINS, new LinkedList<>());
        put(TlsAnalyzedProperty.LIST_STATIC_ECDSA_PKGROUPS, ecdsaPkGroupsStatic);
        put(TlsAnalyzedProperty.LIST_EPHEMERAL_ECDSA_PKGROUPS, ecdsaPkGroupsEphemeral);
    }
}